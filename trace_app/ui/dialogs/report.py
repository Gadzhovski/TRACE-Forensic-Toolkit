"""Case ▸ Create Report: what goes in, how it looks, where it goes.

Three tabs. *Details* -- title, case number, examiner, organisation,
classification line, logo, and the examiner's own summary and conclusions.
*Contents* -- a preset to start from, the sections ticked and dragged into
order with what the case holds for each (counted on a thread), each with
its options beside it (grade threshold, rows per table, which activity,
which part of the timeline, pictures, carved files' order, the external
tools' runs and whether their own reports are copied). *Output* -- HTML,
PDF, Word, which images, the folder, templates.

The choices are remembered per case (``case.setting('report_options')``),
and a template carries them to another case without the case's own text.
The report itself is made by a background job (core/report.py).
"""

import logging
import os
import sqlite3

from PySide6.QtCore import Qt, QThread, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QDialog, QDialogButtonBox,
                               QFileDialog, QFormLayout, QGroupBox,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QPlainTextEdit, QPushButton,
                               QSpinBox, QStackedWidget, QTabWidget,
                               QVBoxLayout, QWidget)

from trace_app.core import report as report_core
from trace_app.core import timeline
from trace_app.ui import icons
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.widgets.kept_threads import KeptThreads
from trace_app.ui.widgets.multi_select import MultiSelectButton

logger = logging.getLogger('TRACE.ReportDialog')

_GRADES = (("Suspicious only", 'suspicious'),
           ("Suspicious and notable", 'notable'),
           ("Everything recorded", 'all'))

#: Where the Contents tab can start: (name, the sections ticked; None =
#: every section). Ticking by hand afterwards shows "Custom".
PRESETS = (
    ("Standard", tuple(s['key'] for s in report_core.default_options()
                       ['sections'] if s['enabled'])),
    ("Full report", None),
    ("Findings summary", ('summary', 'evidence', 'bookmarks', 'tags',
                          'findings', 'hashes', 'persistence', 'methods')),
    ("The examiner's marks", ('summary', 'evidence', 'bookmarks', 'tags',
                              'conversations', 'timeline', 'methods')),
)
CUSTOM = "Custom"

_CARVED_ORDERS = (("Pictures and documents first", 'kind'),
                  ("Disk order", 'offset'))
_MODULE_LISTINGS = (("Artifacts with rows", 'rows'),
                    ("Every artifact", 'all'),
                    ("None (counts only)", 'none'))


class _Counts(QThread):
    """What each section would hold, read on its own read-only connection
    (as the Activity tab reads), and what copying each tool's report would
    write -- the dialog never waits on the case or the disk."""

    counted = Signal(int, object, object)

    def __init__(self, folder, evidence_ids, runs, generation, parent=None):
        super().__init__(parent)
        self.folder, self.evidence_ids = folder, evidence_ids
        self.runs, self.generation = runs, generation

    def run(self):
        from trace_app.core import report_attach
        from trace_app.infra.sqlite_uri import connect_read_only
        from trace_app.core.case import CASE_DB_NAME
        counts, sizes = {}, {}
        try:
            connection = connect_read_only(
                os.path.join(self.folder, CASE_DB_NAME))
            try:
                counts = report_core.section_counts(
                    connection, self.evidence_ids, self.folder)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.warning("Report sections not counted: %s", exc)
        for run in self.runs:
            try:
                _files, pages, _skipped = report_attach.plan(run)
                database = os.path.join(run.get('path') or '', 'report',
                                        report_attach.DATABASE)
                sizes[run['id']] = (pages, os.path.getsize(database)
                                    if os.path.isfile(database) else 0)
            except OSError:
                sizes[run['id']] = (0, 0)
        self.counted.emit(self.generation, counts, sizes)


def _spin(value, low=1, high=100000, suffix=''):
    box = QSpinBox()
    box.setRange(low, high)
    box.setValue(int(value))
    if suffix:
        box.setSuffix(suffix)
    return box


def _utc_edit(text):
    from trace_app.ui.widgets.date_fields import utc_edit
    return utc_edit(text=text)


class ReportDialog(QDialog):
    """Choose the report; `options` holds the choice when accepted."""

    def __init__(self, case, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Report")
        self.setObjectName("reportDialog")
        self.setWindowIcon(icons.icon(icons.REPORT))
        self.setMinimumSize(820, 620)
        self.case = case
        self.options = report_core.default_options(case)
        # Who the examiner is (Options > Settings), where the report has
        # not been given one yet.
        from trace_app.core import settings
        for key in ('examiner', 'organisation'):
            if not self.options.get(key):
                self.options[key] = settings.user(key)
        stored = case.setting('report_options') if case else None
        if stored:
            self._merge(stored)
        #: The external tools' runs (small rows; their sizes are read on
        #: the counting thread).
        self.runs = case.module_runs() if case is not None else []
        self.counts, self.sizes = {}, {}
        self._threads = KeptThreads(self)
        self._generation = 0

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Choose what the report holds. It is written to a folder of its "
            "own -- HTML, PDF and/or Word, with the external tools' own "
            "reports beside it; each file's SHA-256 is recorded in the "
            "audit trail.")
        intro.setObjectName("analysisModulesIntro")
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        layout.addWidget(intro)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("reportTabs")
        self.tabs.addTab(self._details_tab(), "Details")
        self.tabs.addTab(self._contents_tab(), "Contents")
        self.tabs.addTab(self._output_tab(), "Output")
        layout.addWidget(self.tabs, 1)

        buttons = QDialogButtonBox()
        self.create_button = buttons.addButton("Create Report",
                                               QDialogButtonBox.AcceptRole)
        buttons.addButton(QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.recount()

    def done(self, result):
        self._threads.clear()
        super().done(result)

    # --- what each section holds -------------------------------------------

    def recount(self):
        """Count again for the evidence chosen; the answer arrives in
        `_counted` (a newer count wins)."""
        if self.case is None:
            return
        self._generation += 1
        thread = _Counts(self.case.folder, self._evidence_ids(), self.runs,
                         self._generation)
        thread.counted.connect(self._counted)
        self._threads[self._generation] = thread
        thread.start()

    @Slot(int, object, object)
    def _counted(self, generation, counts, sizes):
        if generation != self._generation:
            return
        self.counts, self.sizes = counts or {}, sizes or {}
        self._label_sections()
        self._show_sizes()

    def _label_sections(self):
        titles = {k: t for k, t, _n in report_core.SECTIONS}
        for index in range(self.section_list.count()):
            item = self.section_list.item(index)
            key = item.data(Qt.UserRole)
            count = self.counts.get(key)
            label = titles.get(key, key)
            if count == 0:
                label += "  —  nothing in the case yet"
                item.setToolTip("Left out of the report while 'Leave out "
                                "sections with nothing in them' is ticked")
            elif count:
                label += f"  —  {count:,}"
                item.setToolTip('')
            item.setText(label)

    def _merge(self, stored):
        known = {s['key'] for s in self.options['sections']}
        for key, value in stored.items():
            if key in self.options:
                self.options[key] = value
        sections = [s for s in self.options['sections']
                    if s.get('key') in known]
        present = {s['key'] for s in sections}
        sections += [{'key': k, 'enabled': False}
                     for k, _t, _n in report_core.SECTIONS
                     if k not in present]
        self.options['sections'] = sections

    # --- details ---------------------------------------------------------------

    def _details_tab(self):
        o = self.options
        page = QWidget()
        form = QFormLayout(page)
        self.title_edit = QLineEdit(o.get('title') or '')
        form.addRow("Report title:", self.title_edit)
        self.case_name_edit = QLineEdit(o.get('case_name') or '')
        form.addRow("Case:", self.case_name_edit)
        self.case_number_edit = QLineEdit(o.get('case_number') or '')
        form.addRow("Case number:", self.case_number_edit)
        self.examiner_edit = QLineEdit(o.get('examiner') or '')
        form.addRow("Examiner:", self.examiner_edit)
        self.organisation_edit = QLineEdit(o.get('organisation') or '')
        form.addRow("Organisation:", self.organisation_edit)
        self.classification_edit = QLineEdit(o.get('classification') or '')
        self.classification_edit.setPlaceholderText(
            "e.g. CONFIDENTIAL -- on every page when set")
        form.addRow("Classification:", self.classification_edit)
        logo_row = QHBoxLayout()
        self.logo_edit = QLineEdit(o.get('logo_path') or '')
        self.logo_edit.setPlaceholderText("Optional: your organisation's "
                                          "logo")
        logo_row.addWidget(self.logo_edit, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_logo)
        logo_row.addWidget(browse)
        form.addRow("Logo:", logo_row)
        self.summary_edit = QPlainTextEdit(o.get('summary') or '')
        self.summary_edit.setPlaceholderText(
            "What was asked, what was examined, what was found -- in the "
            "examiner's words.")
        self.summary_edit.setMinimumHeight(90)
        form.addRow("Summary:", self.summary_edit)
        self.conclusions_edit = QPlainTextEdit(o.get('conclusions') or '')
        self.conclusions_edit.setMinimumHeight(70)
        form.addRow("Conclusions:", self.conclusions_edit)
        return page

    def _browse_logo(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Logo", "", "Pictures (*.png *.jpg *.jpeg *.bmp *.gif)")
        if path:
            self.logo_edit.setText(path)

    # --- contents --------------------------------------------------------------

    def _contents_tab(self):
        o = self.options
        page = QWidget()
        row = QHBoxLayout(page)
        left = QVBoxLayout()
        start = QHBoxLayout()
        start.addWidget(QLabel("Start from:"))
        self.preset_combo = QComboBox()
        for name, _keys in PRESETS:
            self.preset_combo.addItem(name)
        self.preset_combo.addItem(CUSTOM)
        self.preset_combo.setToolTip("Tick the sections of a usual report; "
                                     "change any of them afterwards")
        start.addWidget(self.preset_combo, 1)
        left.addLayout(start)
        self.section_list = QListWidget()
        self.section_list.setObjectName("reportSections")
        self.section_list.setDragDropMode(QAbstractItemView.InternalMove)
        self.section_list.setMinimumWidth(270)
        titles = {k: t for k, t, _n in report_core.SECTIONS}
        for section in o['sections']:
            item = QListWidgetItem(titles.get(section['key'],
                                              section['key']))
            item.setData(Qt.UserRole, section['key'])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable
                          | Qt.ItemIsDragEnabled)
            item.setCheckState(Qt.Checked if section.get('enabled')
                               else Qt.Unchecked)
            self.section_list.addItem(item)
        left.addWidget(self.section_list, 1)
        moves = QHBoxLayout()
        for label, step in (("Move Up", -1), ("Move Down", 1)):
            button = QPushButton(label)
            button.clicked.connect(lambda _c=False, s=step: self._move(s))
            moves.addWidget(button)
        all_button = QPushButton("All")
        all_button.clicked.connect(lambda: self._tick_all(True))
        moves.addWidget(all_button)
        none_button = QPushButton("None")
        none_button.clicked.connect(lambda: self._tick_all(False))
        moves.addWidget(none_button)
        left.addLayout(moves)
        self.skip_empty_box = QCheckBox("Leave out sections with nothing "
                                        "in them")
        self.skip_empty_box.setToolTip(
            "A ticked section the case holds nothing for is not printed; "
            "Methods and tools names it, so its absence is not taken for "
            "an omission")
        self.skip_empty_box.setChecked(bool(o.get('skip_empty', True)))
        left.addWidget(self.skip_empty_box)
        row.addLayout(left)
        self._sync_preset()
        self.preset_combo.currentIndexChanged.connect(self._preset_chosen)
        self.section_list.itemChanged.connect(lambda _i: self._sync_preset())

        right = QVBoxLayout()
        self.section_note = QLabel()
        self.section_note.setObjectName("analysisModuleNote")
        self.section_note.setWordWrap(True)
        right.addWidget(self.section_note)
        self.section_options = QStackedWidget()
        self._option_pages = {}
        for key, _title, _note in report_core.SECTIONS:
            widget = self._section_options(key)
            self._option_pages[key] = self.section_options.addWidget(widget)
        right.addWidget(self.section_options, 1)
        row.addLayout(right, 1)
        self.section_list.currentRowChanged.connect(self._section_chosen)
        self.section_list.setCurrentRow(0)
        return page

    def _section_options(self, key):
        o = self.options
        page = QGroupBox("Options")
        form = QFormLayout(page)
        # The examiner's own heading and standing text for the section
        # (kept in a template with it): a methodology note, a caveat.
        section = next((s for s in o['sections'] if s.get('key') == key),
                       {})
        title = QLineEdit(section.get('title') or '')
        title.setPlaceholderText(dict((k, t) for k, t, _n in
                                      report_core.SECTIONS).get(key, key))
        title.setToolTip("Leave empty for the standard heading")
        form.addRow("Heading:", title)
        text = QPlainTextEdit(section.get('text') or '')
        text.setPlaceholderText("Text shown at the start of this section, "
                                "under its heading (optional)")
        text.setFixedHeight(70)
        form.addRow("Section text:", text)
        if not hasattr(self, 'section_custom'):
            self.section_custom = {}
        self.section_custom[key] = (title, text)
        if key in ('bookmarks', 'carved'):
            box = QCheckBox("Include pictures (scaled, never cropped)")
            box.setChecked(bool(o.get('thumbnails')))
            box.toggled.connect(lambda on: self._set('thumbnails', on))
            form.addRow(box)
            size = _spin(o.get('thumbnail_size') or 180, 64, 600, ' px')
            size.valueChanged.connect(lambda v: self._set('thumbnail_size',
                                                          v))
            form.addRow("Picture size:", size)
            setattr(self, f'{key}_pictures', (box, size))
        if key == 'carved':
            limit = _spin(o.get('carved_limit') or 200)
            limit.valueChanged.connect(lambda v: self._set('carved_limit', v))
            form.addRow("Files listed:", limit)
            self.carved_order = QComboBox()
            for label, value in _CARVED_ORDERS:
                self.carved_order.addItem(label, value)
            self.carved_order.setCurrentIndex(max(0, self.carved_order.findData(
                o.get('carved_order') or 'kind')))
            self.carved_order.setToolTip(
                "By kind: pictures, documents, mail and media first, "
                "file-system records ($MFT entries, index and hive pieces) "
                "last -- within each, the best proved first")
            form.addRow("List first:", self.carved_order)
            from trace_app.core.carve_verify import STATUS_LABELS
            chosen = set(o.get('carved_statuses') or STATUS_LABELS)
            self.carved_statuses = {}
            statuses = QHBoxLayout()
            for status in ('complete', 'valid', 'reconstructed', 'partial'):
                box = QCheckBox(STATUS_LABELS.get(status, status))
                box.setChecked(status in chosen)
                self.carved_statuses[status] = box
                statuses.addWidget(box)
            statuses.addStretch(1)
            form.addRow("Include:", statuses)
        if key == 'modules':
            self._module_page(form)
        if key in ('findings', 'ntfs'):
            if key == 'findings':
                self.grade_combo = QComboBox()
                for label, value in _GRADES:
                    self.grade_combo.addItem(label, value)
                self.grade_combo.setCurrentIndex(max(0, self.grade_combo
                                                     .findData(o.get(
                                                         'findings_grade'))))
                form.addRow("Findings graded:", self.grade_combo)
            limit = _spin(o.get('findings_limit') or 200)
            limit.valueChanged.connect(lambda v: self._set('findings_limit',
                                                           v))
            form.addRow("Rows per table:", limit)
        if key == 'activity':
            from trace_app.core.activity import CATEGORIES
            chosen = set(o.get('activity_categories') or
                         [k for k, _l in CATEGORIES])
            self.activity_boxes = {}
            for category, label in CATEGORIES:
                box = QCheckBox(label)
                box.setChecked(category in chosen)
                self.activity_boxes[category] = box
                form.addRow(box)
            self.activity_limit = _spin(o.get('activity_limit') or 50)
            form.addRow("Newest records per kind:", self.activity_limit)
        if key == 'timeline':
            picked = len(self.case.report_items('timeline')) \
                if self.case else 0
            self.timeline_items_box = QCheckBox(
                f"Events added from the Timeline tab ({picked})")
            self.timeline_items_box.setChecked(bool(o.get('timeline_items',
                                                          True)))
            clear = QPushButton("Clear")
            clear.setEnabled(bool(picked))
            clear.setToolTip("Forget the events added from the Timeline "
                             "(right-click ▸ Add to Report there)")
            clear.clicked.connect(lambda: self._clear_picked(clear))
            form.addRow(self.timeline_items_box)
            starred = len(self.case.timeline_marks(starred_only=True)) \
                if self.case is not None else 0
            self.timeline_starred_box = QCheckBox(
                f"Starred events, with your comments ({starred})")
            self.timeline_starred_box.setChecked(bool(o.get(
                'timeline_starred', True)))
            self.timeline_chart_box = QCheckBox(
                "A chart of the timeline (around the starred events)")
            self.timeline_chart_box.setChecked(bool(o.get('timeline_chart',
                                                          True)))
            row = QHBoxLayout()
            row.addSpacing(22)
            row.addWidget(clear)
            row.addStretch(1)
            form.addRow(row)
            form.addRow(self.timeline_starred_box)
            form.addRow(self.timeline_chart_box)
            self.timeline_range_box = QCheckBox("Every event in a range:")
            self.timeline_range_box.setChecked(bool(o.get('timeline_range')))
            form.addRow(self.timeline_range_box)
            start, end = o.get('timeline_start'), o.get('timeline_end')
            if not start and self.case is not None:
                # Open on the case's own span rather than an arbitrary date.
                try:
                    first, last, _outside = timeline.bounds(
                        self.case._db, timeline.default_filters())
                    start, end = first, last
                except Exception:
                    start = end = None
            self.timeline_start = _utc_edit(start)
            self.timeline_end = _utc_edit(end)
            form.addRow("From (UTC):", self.timeline_start)
            form.addRow("To (UTC):", self.timeline_end)
            self.timeline_limit = _spin(o.get('timeline_limit') or 500)
            form.addRow("At most:", self.timeline_limit)
            chosen = set(o.get('timeline_sources') or
                         timeline.default_filters()['sources'])
            self.timeline_sources = {}
            for source, label, _colour in timeline.SOURCES:
                box = QCheckBox(label)
                box.setChecked(source in chosen)
                self.timeline_sources[source] = box
                form.addRow(box)
            for widget in (self.timeline_start, self.timeline_end,
                           self.timeline_limit,
                           *self.timeline_sources.values()):
                widget.setEnabled(self.timeline_range_box.isChecked())
                self.timeline_range_box.toggled.connect(widget.setEnabled)
        if key == 'indicators':
            limit = _spin(o.get('indicator_limit') or 25)
            limit.valueChanged.connect(lambda v: self._set('indicator_limit',
                                                           v))
            form.addRow("Values per kind:", limit)
        if key == 'audit':
            limit = _spin(o.get('audit_limit') or 5000, 10, 1000000)
            limit.valueChanged.connect(lambda v: self._set('audit_limit', v))
            form.addRow("Entries, at most:", limit)
        return page

    def _module_page(self, form):
        o = self.options
        self.module_runs_list = QListWidget()
        self.module_runs_list.setObjectName("reportModuleRuns")
        picked = {int(i) for i in o.get('module_runs') or ()}
        names = {}
        if self.case is not None:
            names = {r['id']: r.get('display_name')
                     or os.path.basename(r['path'])
                     for r in self.case.evidence()}
        for run in self.runs:
            item = QListWidgetItem(
                f"{run['tool']} {run.get('version') or ''} — "
                f"{names.get(run.get('evidence_id'), '?')}")
            item.setToolTip(f"Run {run['id']}: {run.get('status')}, "
                            f"started {run.get('started_utc') or '?'} UTC\n"
                            f"{run.get('message') or ''}")
            item.setData(Qt.UserRole, run['id'])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if not picked or run['id'] in picked
                               else Qt.Unchecked)
            self.module_runs_list.addItem(item)
        self.module_runs_list.setMaximumHeight(120)
        if not self.runs:
            form.addRow(QLabel("No external module has been run in this "
                               "case."))
        form.addRow("Runs:", self.module_runs_list)
        self.module_runs_list.setVisible(bool(self.runs))
        label = form.labelForField(self.module_runs_list)
        if label is not None:
            label.setVisible(bool(self.runs))
        self.module_listing = QComboBox()
        for label, value in _MODULE_LISTINGS:
            self.module_listing.addItem(label, value)
        self.module_listing.setCurrentIndex(max(0, self.module_listing
                                                .findData(o.get(
                                                    'module_artifacts')
                                                    or 'rows')))
        self.module_listing.setToolTip(
            "Which of each run's artifacts are listed in this report; the "
            "tool's own report lists every one")
        form.addRow("Listed:", self.module_listing)
        self.copy_reports_box = QCheckBox(
            "Copy each tool's own report into the report's folder")
        self.copy_reports_box.setToolTip(
            "Its HTML pages, timeline, TSV exports and media, hashed into "
            "MANIFEST.csv and linked from this report. Never its copies of "
            "the evidence files (data/).")
        self.copy_reports_box.setChecked(bool(o.get('copy_tool_reports',
                                                    True)))
        form.addRow(self.copy_reports_box)
        self.module_database_box = QCheckBox(
            "… with its database (_lava_artifacts.db, every row it "
            "extracted)")
        self.module_database_box.setChecked(bool(o.get('module_database')))
        form.addRow(self.module_database_box)
        self.copy_size = QLabel()
        self.copy_size.setObjectName("analysisModuleNote")
        self.copy_size.setWordWrap(True)
        form.addRow(self.copy_size)
        self.copy_reports_box.toggled.connect(
            self.module_database_box.setEnabled)
        self.module_database_box.setEnabled(self.copy_reports_box.isChecked())
        for signal in (self.copy_reports_box.toggled,
                       self.module_database_box.toggled):
            signal.connect(lambda _on: self._show_sizes())
        self.module_runs_list.itemChanged.connect(
            lambda _i: self._show_sizes())

    def _chosen_run_ids(self):
        ids = [self.module_runs_list.item(i).data(Qt.UserRole)
               for i in range(self.module_runs_list.count())
               if self.module_runs_list.item(i).checkState() == Qt.Checked]
        # Every run ticked: none named, so a later run is in too.
        return [] if len(ids) == self.module_runs_list.count() else ids

    def _show_sizes(self):
        label = getattr(self, 'copy_size', None)
        if label is None:
            return
        if not self.runs:
            label.setText('')
            return
        if not self.copy_reports_box.isChecked():
            label.setText("The report will name each tool's report in the "
                          "case folder.")
            return
        if not self.sizes:
            label.setText("Measuring the tools' reports…")
            return
        chosen = set(self._chosen_run_ids()) or {r['id'] for r in self.runs}
        pages = sum(self.sizes.get(i, (0, 0))[0] for i in chosen)
        database = sum(self.sizes.get(i, (0, 0))[1] for i in chosen)
        text = f"About {report_core._size(pages)} to copy"
        if self.module_database_box.isChecked():
            text = (f"About {report_core._size(pages + database)} to copy "
                    f"(the databases are {report_core._size(database)})")
        elif database:
            text += f"; the databases would add {report_core._size(database)}"
        label.setText(text + ".")

    def _clear_picked(self, button):
        items = self.case.report_items('timeline')
        self.case.remove_report_items([item['id'] for item in items])
        self.timeline_items_box.setText(
            "Events added from the Timeline tab (0)")
        button.setEnabled(False)

    def _set(self, key, value):
        self.options[key] = value
        # Pictures are one choice, shown on two pages.
        if key in ('thumbnails', 'thumbnail_size'):
            for pair in (getattr(self, 'bookmarks_pictures', None),
                         getattr(self, 'carved_pictures', None)):
                if pair is None:
                    continue
                box, size = pair
                widget = box if key == 'thumbnails' else size
                widget.blockSignals(True)
                (widget.setChecked if key == 'thumbnails'
                 else widget.setValue)(value)
                widget.blockSignals(False)

    def _section_chosen(self, row):
        item = self.section_list.item(row)
        if item is None:
            return
        key = item.data(Qt.UserRole)
        notes = {k: n for k, _t, n in report_core.SECTIONS}
        self.section_note.setText(notes.get(key, ''))
        self.section_options.setCurrentIndex(self._option_pages[key])

    def _move(self, step):
        row = self.section_list.currentRow()
        target = row + step
        if row < 0 or not 0 <= target < self.section_list.count():
            return
        item = self.section_list.takeItem(row)
        self.section_list.insertItem(target, item)
        self.section_list.setCurrentRow(target)

    def _tick_all(self, on):
        for index in range(self.section_list.count()):
            self.section_list.item(index).setCheckState(
                Qt.Checked if on else Qt.Unchecked)

    def _ticked(self):
        return {self.section_list.item(i).data(Qt.UserRole)
                for i in range(self.section_list.count())
                if self.section_list.item(i).checkState() == Qt.Checked}

    def _preset_chosen(self, index):
        if not 0 <= index < len(PRESETS):
            return                      # Custom: leave the ticks alone
        keys = PRESETS[index][1]
        every = {k for k, _t, _n in report_core.SECTIONS}
        wanted = every if keys is None else set(keys)
        for i in range(self.section_list.count()):
            item = self.section_list.item(i)
            item.setCheckState(Qt.Checked if item.data(Qt.UserRole) in wanted
                               else Qt.Unchecked)
        self._sync_preset()

    def _sync_preset(self):
        """Show the preset the ticks match, else Custom."""
        ticked = self._ticked()
        every = {k for k, _t, _n in report_core.SECTIONS}
        index = next((i for i, (_name, keys) in enumerate(PRESETS)
                      if ticked == (every if keys is None else set(keys))),
                     len(PRESETS))
        self.preset_combo.blockSignals(True)
        self.preset_combo.setCurrentIndex(index)
        self.preset_combo.blockSignals(False)

    # --- output ------------------------------------------------------------------

    def _output_tab(self):
        o = self.options
        page = QWidget()
        form = QFormLayout(page)
        formats = QHBoxLayout()
        self.html_box = QCheckBox("HTML (one self-contained file)")
        self.html_box.setChecked('html' in (o.get('formats') or ()))
        self.pdf_box = QCheckBox("PDF (A4, contents and page numbers)")
        self.pdf_box.setChecked('pdf' in (o.get('formats') or ()))
        self.docx_box = QCheckBox("Word (.docx, to edit)")
        self.docx_box.setChecked('docx' in (o.get('formats') or ()))
        formats.addWidget(self.html_box)
        formats.addWidget(self.pdf_box)
        formats.addWidget(self.docx_box)
        formats.addStretch(1)
        form.addRow("Formats:", formats)
        evidence = self.case.evidence() if self.case else []
        #: Evidence label -> id; labels are made unique (two images can
        #: share a file name).
        self._evidence_labels = {}
        for row in evidence:
            label = row.get('display_name') or os.path.basename(row['path'])
            if label in self._evidence_labels:
                label = f"{label} (#{row['id']})"
            self._evidence_labels[label] = row['id']
        self.evidence_button = MultiSelectButton(
            list(self._evidence_labels), noun="images")
        chosen = o.get('evidence_ids')
        self.evidence_button.blockSignals(True)
        self.evidence_button.set_selected(
            [label for label, i in self._evidence_labels.items()
             if chosen is None or i in chosen])
        self.evidence_button.blockSignals(False)
        self.evidence_button.selectionChanged.connect(
            lambda _names: self.recount())
        form.addRow("Evidence:", self.evidence_button)
        where = QHBoxLayout()
        self.folder_edit = QLineEdit(o.get('folder') or '')
        self.folder_edit.setPlaceholderText(
            os.path.join(self.case.folder, 'exports') if self.case else '')
        where.addWidget(self.folder_edit, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_folder)
        where.addWidget(browse)
        form.addRow("Written to:", where)
        note = QLabel("Each report is written to a folder of its own, "
                      "'Report <date> <time>', inside this one.")
        note.setObjectName("analysisModuleNote")
        note.setWordWrap(True)
        form.addRow("", note)
        templates = QHBoxLayout()
        save = QPushButton("Save as Template…")
        save.clicked.connect(self._save_template)
        load = QPushButton("Load Template…")
        load.clicked.connect(self._load_template)
        templates.addWidget(save)
        templates.addWidget(load)
        templates.addStretch(1)
        form.addRow("Templates:", templates)
        note = QLabel("A template keeps the sections, their order and "
                      "options, the organisation, logo and classification -- "
                      "not this case's name, number or text.")
        note.setObjectName("analysisModuleNote")
        note.setWordWrap(True)
        form.addRow("", note)
        return page

    def _browse_folder(self):
        start = self.folder_edit.text().strip() or \
            self.folder_edit.placeholderText()
        path = QFileDialog.getExistingDirectory(self, "Write Reports To",
                                                start)
        if path:
            self.folder_edit.setText(path)

    def _evidence_ids(self):
        """The chosen images' ids; None when every one is chosen."""
        button = getattr(self, 'evidence_button', None)
        if button is None or button.all_selected():
            return None
        return [self._evidence_labels[label] for label in button.selected()]

    def _save_template(self):
        from trace_app.infra.paths import user_config_dir
        folder = os.path.join(user_config_dir(), 'report-templates')
        os.makedirs(folder, exist_ok=True)
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report Template",
            os.path.join(folder, 'template.json'), "Template (*.json)")
        if path:
            report_core.save_template(self.collected(), path)

    def _load_template(self):
        from trace_app.infra.paths import user_config_dir
        folder = os.path.join(user_config_dir(), 'report-templates')
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Report Template", folder, "Template (*.json)")
        if not path:
            return
        try:
            loaded = report_core.load_template(path, self.case)
        except (OSError, ValueError) as exc:
            from trace_app.ui.dialogs import message
            message.warning(self, "Template not loaded", str(exc))
            return
        keep = self.collected()
        # The case's own text and choices stay; a template carries none.
        for key in ('case_name', 'case_number', 'summary', 'conclusions',
                    'examiner', 'evidence_ids', 'folder', 'module_runs'):
            loaded[key] = keep[key]
        self.options = loaded
        current = self.tabs.currentIndex()
        for index in range(self.tabs.count() - 1, -1, -1):
            self.tabs.removeTab(index)
        self.tabs.addTab(self._details_tab(), "Details")
        self.tabs.addTab(self._contents_tab(), "Contents")
        self.tabs.addTab(self._output_tab(), "Output")
        self.tabs.setCurrentIndex(current)
        self.recount()

    # --- the result ----------------------------------------------------------------

    def collected(self):
        options = dict(self.options)
        options.update(
            title=self.title_edit.text().strip() or 'Forensic Examination '
                                                    'Report',
            case_name=self.case_name_edit.text().strip(),
            case_number=self.case_number_edit.text().strip(),
            examiner=self.examiner_edit.text().strip(),
            organisation=self.organisation_edit.text().strip(),
            classification=self.classification_edit.text().strip(),
            logo_path=self.logo_edit.text().strip(),
            summary=self.summary_edit.toPlainText().strip(),
            conclusions=self.conclusions_edit.toPlainText().strip(),
            sections=[self._section_entry(i)
                      for i in range(self.section_list.count())],
            formats=[f for f, box in (('html', self.html_box),
                                      ('pdf', self.pdf_box),
                                      ('docx', self.docx_box))
                     if box.isChecked()],
            findings_grade=self.grade_combo.currentData(),
            activity_categories=[k for k, box in self.activity_boxes.items()
                                 if box.isChecked()],
            activity_limit=self.activity_limit.value(),
            timeline_items=self.timeline_items_box.isChecked(),
            timeline_starred=self.timeline_starred_box.isChecked(),
            timeline_chart=self.timeline_chart_box.isChecked(),
            timeline_range=self.timeline_range_box.isChecked(),
            timeline_start=self.timeline_start.dateTime().toUTC().toString(
                "yyyy-MM-dd HH:mm:ss"),
            timeline_end=self.timeline_end.dateTime().toUTC().toString(
                "yyyy-MM-dd HH:mm:ss"),
            timeline_limit=self.timeline_limit.value(),
            timeline_sources=[k for k, box in self.timeline_sources.items()
                              if box.isChecked()],
            evidence_ids=self._evidence_ids(),
            folder=self.folder_edit.text().strip(),
            skip_empty=self.skip_empty_box.isChecked(),
            carved_order=self.carved_order.currentData(),
            # Every status ticked: none named, so nothing is filtered.
            carved_statuses=[] if all(
                box.isChecked() for box in self.carved_statuses.values())
            else [k for k, box in self.carved_statuses.items()
                  if box.isChecked()],
            module_runs=self._chosen_run_ids(),
            module_artifacts=self.module_listing.currentData(),
            copy_tool_reports=self.copy_reports_box.isChecked(),
            module_database=self.module_database_box.isChecked(),
        )
        return options

    def _section_entry(self, row):
        item = self.section_list.item(row)
        key = item.data(Qt.UserRole)
        entry = {'key': key, 'enabled': item.checkState() == Qt.Checked}
        title, text = getattr(self, 'section_custom', {}).get(key,
                                                              (None, None))
        if title is not None and title.text().strip():
            entry['title'] = title.text().strip()
        if text is not None and text.toPlainText().strip():
            entry['text'] = text.toPlainText().strip()
        return entry

    def _accept(self):
        options = self.collected()
        if not options['formats']:
            self.tabs.setCurrentIndex(2)
            self.html_box.setFocus()
            return
        if not any(s['enabled'] for s in options['sections']):
            self.tabs.setCurrentIndex(1)
            return
        if options['evidence_ids'] == []:
            self.tabs.setCurrentIndex(2)
            self.evidence_button.setFocus()
            return
        if options['carved_statuses'] == [] and not any(
                box.isChecked() for box in self.carved_statuses.values()):
            self.tabs.setCurrentIndex(1)
            return
        self.options = options
        if self.case is not None:
            self.case.set_setting('report_options', options)
        self.accept()


class ReportWorker(ProcessWorker):
    """Writes the report in a child process (core/background.py)."""

    progressed = Signal(object, object, str)
    item_written = Signal(dict)
    finished_report = Signal(int, str)

    kind = 'report'

    def __init__(self, case_folder, options, images, parent=None):
        super().__init__({'case_folder': case_folder, 'options': options,
                          'images': images}, parent)

    def on_progress(self, done, total, what):
        self.progressed.emit(done, total, what)

    def on_item(self, record):
        self.item_written.emit(record)

    def on_done(self, count, error):
        self.finished_report.emit(count, error)


class ReportDoneDialog(QDialog):
    """Where the report is, its hashes, and a way to open it."""

    opened = Signal(str)

    def __init__(self, written, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Report Created")
        self.setObjectName("reportDoneDialog")
        self.setWindowIcon(icons.icon(icons.REPORT))
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        heading = QLabel("<b>The report is ready.</b> Its SHA-256 is "
                         "recorded in the case's audit trail.")
        heading.setTextFormat(Qt.RichText)
        layout.addWidget(heading)
        form = QFormLayout()
        if written and written[0].get('folder'):
            where = QLabel(written[0]['folder'])
            where.setTextInteractionFlags(Qt.TextSelectableByMouse)
            where.setWordWrap(True)
            form.addRow("Folder:", where)
        for item in written:
            label = item['format'].upper() + (
                f" ({item['pages']} pages)" if item.get('pages') else '')
            text = QLabel(f"{item['path']}\nSHA-256 {item['sha256']}")
            text.setTextInteractionFlags(Qt.TextSelectableByMouse)
            text.setWordWrap(True)
            form.addRow(f"{label}:", text)
        layout.addLayout(form)
        buttons = QDialogButtonBox()
        for item in written:
            button = buttons.addButton(f"Open {item['format'].upper()}",
                                       QDialogButtonBox.ActionRole)
            button.clicked.connect(
                lambda _c=False, p=item['path']: self._open(p))
        if written:
            folder = buttons.addButton("Open Folder",
                                       QDialogButtonBox.ActionRole)
            folder.clicked.connect(lambda: self._open(os.path.dirname(
                written[0]['path'])))
        close = buttons.addButton(QDialogButtonBox.Close)
        close.clicked.connect(self.accept)
        layout.addWidget(buttons)

    def _open(self, path):
        self.opened.emit(path)
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))
