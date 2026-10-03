"""Case ▸ Create Report: what goes in, how it looks, where it goes.

Three tabs. *Details* -- title, case number, examiner, organisation,
classification line, logo, and the examiner's own summary and conclusions.
*Contents* -- the sections, ticked and dragged into order, each with its
options beside it (grade threshold, rows per table, which activity, which
part of the timeline, pictures or not). *Output* -- HTML, PDF or both, which
images, templates.

The choices are remembered per case (``case.setting('report_options')``),
and a template carries them to another case without the case's own text.
The report itself is made by a background job (core/report.py).
"""

import logging
import os

from PySide6.QtCore import QDateTime, Qt, QTimeZone, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QDateTimeEdit, QDialog, QDialogButtonBox,
                               QFileDialog, QFormLayout, QGroupBox,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QPlainTextEdit, QPushButton,
                               QSpinBox, QStackedWidget, QTabWidget,
                               QVBoxLayout, QWidget)

from trace_app.core import report as report_core
from trace_app.core import timeline
from trace_app.ui import icons
from trace_app.ui.process_worker import ProcessWorker

logger = logging.getLogger('TRACE.ReportDialog')

_GRADES = (("Suspicious only", 'suspicious'),
           ("Suspicious and notable", 'notable'),
           ("Everything recorded", 'all'))


def _spin(value, low=1, high=100000, suffix=''):
    box = QSpinBox()
    box.setRange(low, high)
    box.setValue(int(value))
    if suffix:
        box.setSuffix(suffix)
    return box


def _utc_edit(text):
    edit = QDateTimeEdit()
    edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
    edit.setTimeZone(QTimeZone.utc())
    edit.setCalendarPopup(True)
    if text:
        moment = QDateTime.fromString(text[:19], "yyyy-MM-dd HH:mm:ss")
        moment.setTimeZone(QTimeZone.utc())
        edit.setDateTime(moment)
    return edit


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
        stored = case.setting('report_options') if case else None
        if stored:
            self._merge(stored)

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Choose what the report holds. It is written to the case's "
            "<b>exports</b> folder as a self-contained HTML page and/or a "
            "PDF; each file's SHA-256 is recorded in the audit trail.")
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
        row.addLayout(left)

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
            row = QHBoxLayout()
            row.addWidget(self.timeline_items_box)
            row.addWidget(clear)
            row.addStretch(1)
            form.addRow(row)
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
        if form.rowCount() == 0:
            form.addRow(QLabel("Nothing to choose for this section."))
        return page

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
        formats.addWidget(self.html_box)
        formats.addWidget(self.pdf_box)
        formats.addStretch(1)
        form.addRow("Formats:", formats)
        self.scope_combo = QComboBox()
        evidence = self.case.evidence() if self.case else []
        if len(evidence) > 1:
            self.scope_combo.addItem(f"All {len(evidence)} images", None)
        for row in evidence:
            self.scope_combo.addItem(row.get('display_name')
                                     or os.path.basename(row['path']),
                                     [row['id']])
        chosen = o.get('evidence_ids')
        if chosen:
            self.scope_combo.setCurrentIndex(max(0, self.scope_combo
                                                 .findData(chosen)))
        form.addRow("Evidence:", self.scope_combo)
        folder = os.path.join(self.case.folder, 'exports') if self.case \
            else ''
        where = QLabel(folder)
        where.setTextInteractionFlags(Qt.TextSelectableByMouse)
        form.addRow("Written to:", where)
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
        for key in ('case_name', 'case_number', 'summary', 'conclusions',
                    'examiner'):
            loaded[key] = keep[key]
        self.options = loaded
        current = self.tabs.currentIndex()
        for index in range(self.tabs.count() - 1, -1, -1):
            self.tabs.removeTab(index)
        self.tabs.addTab(self._details_tab(), "Details")
        self.tabs.addTab(self._contents_tab(), "Contents")
        self.tabs.addTab(self._output_tab(), "Output")
        self.tabs.setCurrentIndex(current)

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
            sections=[{'key': self.section_list.item(i).data(Qt.UserRole),
                       'enabled': self.section_list.item(i).checkState()
                       == Qt.Checked}
                      for i in range(self.section_list.count())],
            formats=[f for f, box in (('html', self.html_box),
                                      ('pdf', self.pdf_box))
                     if box.isChecked()],
            findings_grade=self.grade_combo.currentData(),
            activity_categories=[k for k, box in self.activity_boxes.items()
                                 if box.isChecked()],
            activity_limit=self.activity_limit.value(),
            timeline_items=self.timeline_items_box.isChecked(),
            timeline_range=self.timeline_range_box.isChecked(),
            timeline_start=self.timeline_start.dateTime().toUTC().toString(
                "yyyy-MM-dd HH:mm:ss"),
            timeline_end=self.timeline_end.dateTime().toUTC().toString(
                "yyyy-MM-dd HH:mm:ss"),
            timeline_limit=self.timeline_limit.value(),
            timeline_sources=[k for k, box in self.timeline_sources.items()
                              if box.isChecked()],
            evidence_ids=self.scope_combo.currentData(),
        )
        return options

    def _accept(self):
        options = self.collected()
        if not options['formats']:
            self.tabs.setCurrentIndex(2)
            self.html_box.setFocus()
            return
        if not any(s['enabled'] for s in options['sections']):
            self.tabs.setCurrentIndex(1)
            return
        self.options = options
        if self.case is not None:
            self.case.set_setting('report_options', options)
        self.accept()


class ReportWorker(ProcessWorker):
    """Writes the report in a child process (core/background.py)."""

    progressed = Signal(int, int, str)
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
