"""Universal search: one place to ask a question of the whole case.

This replaces a search that matched filenames and nothing else. It looks in
file contents, paths, registry values and archive members, and it answers
questions about entities with the email:, url:, ip: and other prefixes.

Building the index is an analysis module (Analysis > Run Analysis Modules),
run on the shared job queue like every other reader of the evidence; the
indicators it extracts are listed in Triage > Indicators and under Findings.
This tab only asks questions of what has been indexed.

Results appear here rather than in the listing table. Overloading the listing
meant search and browsing fought over the same widget: columns were toggled,
browse state was saved and restored, and returning from a search was a mode
change. A separate tab leaves the listing alone.
"""

import logging
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout,
                               QSizePolicy, QToolBar,
                               QHeaderView, QLabel, QLineEdit,
                               QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from trace_app.core.search_index import SearchError, SearchIndex
from trace_app.infra.constants import (CONTROL_HEIGHT, PANEL_ICON_SIZE,
                                      TABLE_ROW_HEIGHT)
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui import icons
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.widgets.row_preview import connect_row_preview
from trace_app.ui.widgets.table_columns import fit_columns
from trace_app.ui.widgets.toolbars import prepare_toolbar

logger = logging.getLogger('TRACE.SearchPanel')

#: The example queries offered in the dropdown. These double as documentation:
#: the syntax is only discoverable if something shows it.
#: What the dropdown offers. These are the searches an examiner actually runs,
#: grouped so the list reads as a menu of questions rather than a syntax
#: reference. The patterns are deliberately conservative: one that matches too
#: much fills the results with noise to be dismissed by hand, which is worse
#: than missing an unusual form.
EXAMPLES = [
    ('— Text —', ''),
    ('Any word', 'invoice'),
    ('An exact phrase', '"wire transfer"'),
    ('Both words', 'invoice AND urgent'),
    ('Either word', 'invoice OR receipt'),
    ('Excluding a word', 'payment NOT refund'),
    ('Starting with', 'invoic*'),

    ('— Files —', ''),
    ('By name', 'name:report'),
    ('By path', 'path:Users'),
    ('By extension', '*.pdf'),
    ('Office documents', '/\\.(docx?|xlsx?|pptx?)$/'),
    ('Archives', '/\\.(zip|rar|7z|tar|gz)$/'),
    ('Databases', '/\\.(db|sqlite3?|mdb|accdb)$/'),

    ('— Contact and network —', ''),
    ('An email address', 'email:example.com'),
    ('Private IPv4 ranges', '/\\b(?:10\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.)\\d{1,3}\\.\\d{1,3}\\b/'),
    ('MAC addresses', '/\\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\\b/'),
    ('UK phone numbers', '/\\b(?:0|\\+?44\\s?)(?:\\d\\s?){9,10}\\b/'),
    ('US phone numbers', '/\\b(?:\\+?1[\\s.-]?)?\\(?\\d{3}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4}\\b/'),

    ('— Financial —', ''),
    ('Credit card numbers', '/\\b(?:4\\d{12}(?:\\d{3})?|5[1-5]\\d{14}|3[47]\\d{13}|6(?:011|5\\d{2})\\d{12})\\b/'),
    ('IBAN', '/\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b/'),
    ('Currency amounts', '/[£$€]\\s?\\d[\\d,]*(?:\\.\\d{2})?/'),

    ('— Identifiers —', ''),
    ('A known hash', 'hash:d41d8cd98f00b204e9800998ecf8427e'),
    ('UK National Insurance', '/\\b[A-CEGHJ-PR-TW-Z]{2}\\d{6}[A-D]\\b/'),
    ('US Social Security', '/\\b\\d{3}-\\d{2}-\\d{4}\\b/'),
    ('GUIDs', '/\\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\\b/'),

    ('— Credentials —', ''),
    ('Password-like assignments', '/(?:password|passwd|pwd)\\s*[:=]\\s*\\S+/'),
    ('API keys and tokens', '/(?:api[_-]?key|secret|token)\\s*[:=]\\s*\\S{8,}/'),
    ('Private key blocks', '"BEGIN RSA PRIVATE KEY" OR "BEGIN PRIVATE KEY"'),

    ('— Dates —', ''),
    ('ISO dates', '/\\b\\d{4}-\\d{2}-\\d{2}\\b/'),
    ('UK/US short dates', '/\\b\\d{1,2}[/-]\\d{1,2}[/-]\\d{2,4}\\b/'),
]


class IndexWorker(ProcessWorker):
    """Builds one image's search index in a child process
    (core/background.py), as a job on the window's queue
    (MainWindow.queue_indexing)."""

    progressed = Signal(int, int, str)
    finished_indexing = Signal(int, str)

    kind = 'index'

    def __init__(self, image_path, case_folder, evidence_id, parent=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id}, parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_indexing.emit(count, error)


class SearchPanel(QWidget):
    """Query the case index, and jump from a result to its evidence."""

    #: Emitted with a result row when the user opens one.
    result_activated = Signal(dict)

    #: Emitted with (row, global position) when a result is right-clicked, so
    #: the host can offer the same bookmark actions the listing has. The panel
    #: does not know about cases; the window does.
    result_menu_requested = Signal(dict, object)

    #: Emitted with a result row when the examiner lands on it.
    result_selected = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self.index = None
        #: Resolves an extension to the icon the listing would use. Injected
        #: by the host so this panel does not reach into a DatabaseManager.
        self.icon_resolver = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # The same bar as Listing, Registry and Deleted Files: logo, title,
        # then the tab's main action on the right. Without it this tab was the
        # only one in the row that opened straight onto controls.
        self.toolbar = QToolBar()
        prepare_toolbar(self.toolbar)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        icon_label = QLabel()
        icon_label.setObjectName("panelIcon")
        icons.apply_pixmap(icon_label, icons.SEARCH_CONTENT, PANEL_ICON_SIZE)
        self.toolbar.addWidget(icon_label)
        title = QLabel("Universal Search")
        title.setObjectName("panelTitle")
        self.toolbar.addWidget(title)
        spacer = QLabel()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)
        outer.addWidget(self.toolbar)

        layout = QVBoxLayout()
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)
        outer.addLayout(layout)

        # --- query row ---
        query_row = QHBoxLayout()
        query_row.setSpacing(6)

        self.query_input = QLineEdit()
        self.query_input.setObjectName("universalSearchBar")
        self.query_input.setPlaceholderText(
            "Search the whole case — text, names, paths, emails, URLs, IPs, "
            "hashes")
        self.query_input.returnPressed.connect(self.run_search)
        query_row.addWidget(self.query_input, 1)

        self.examples = QComboBox()
        self.examples.setObjectName("searchExamples")
        self.examples.setFixedHeight(CONTROL_HEIGHT)
        self.examples.addItem("Search for…", '')
        for label, example in EXAMPLES:
            if not example:
                # A group heading: shown, but not something to choose.
                self.examples.addItem(label, '')
                item = self.examples.model().item(self.examples.count() - 1)
                if item is not None:
                    item.setEnabled(False)
            else:
                self.examples.addItem(f"   {label}", example)
        self.examples.activated.connect(self._use_example)
        query_row.addWidget(self.examples)

        self.search_button = QPushButton("Search")
        self.search_button.setFixedHeight(CONTROL_HEIGHT)
        self.search_button.clicked.connect(self.run_search)
        query_row.addWidget(self.search_button)
        layout.addLayout(query_row)

        # What the index covers -- or, before anything is indexed, how to
        # index it. The indicators themselves are Triage's (Indicators).
        self.summary_label = QLabel()
        self.summary_label.setObjectName("searchSummary")
        self.summary_label.setWordWrap(True)
        self.summary_label.setTextFormat(Qt.RichText)
        layout.addWidget(self.summary_label)

        # The result count. Below the summary rather than beside it, because
        # it changes with every search while the summary stays.
        self.status_label = QLabel()
        self.status_label.setObjectName("searchStatus")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # --- results ---
        self.results = QTableWidget()
        self.results.setObjectName("searchResults")
        # The listing's columns, in the listing's order, plus the matched text
        # -- a result an examiner cannot read without going back to the file
        # is only half an answer.
        self.results.setColumnCount(9)
        self.results.setHorizontalHeaderLabels(
            ['Name', 'Match', 'Type', 'Size', 'Created', 'Accessed',
             'Modified', 'Path', 'Evidence'])
        self.results.verticalHeader().setVisible(False)
        self.results.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.results.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        self.results.itemDoubleClicked.connect(self._activate)
        # A click shows the hit in the viewers and leaves the results where
        # they are; double-click goes to the file's folder.
        connect_row_preview(self.results, self.result_selected.emit)
        self.results.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.results)

        self.set_case(None)

    # --- wiring -----------------------------------------------------------

    def set_case(self, case):
        if self.index is not None:
            self.index.close()
            self.index = None
        self.case = case
        if case is not None:
            try:
                self.index = SearchIndex(case.folder)
            except Exception as exc:
                logger.error("Could not open the search index: %s", exc)
        self._update_status()

    def reload_index(self):
        """Reopen the index after an indexing job has written to it through
        its own connection, and redraw what it covers."""
        self.set_case(self.case)

    def _update_status(self):
        has_case = self.case is not None and self.index is not None
        self.query_input.setEnabled(has_case)
        self.search_button.setEnabled(has_case)

        if not has_case:
            self._set_status(
                "Quick triage — universal search needs a case, because the "
                "index is kept with it. File ▸ New Case starts one.")
            self.summary_label.clear()
            return

        self._set_status()
        self._update_summary()

    def _set_status(self, text=''):
        """Say something below the summary, or take the row back.

        An empty label still occupies a line. In a panel this size that is a
        row of results, so the label is hidden when it has nothing to say.
        """
        self.status_label.setText(text)
        self.status_label.setVisible(bool(text))

    def _update_summary(self):
        """Write what the index holds. Survives every search."""
        if self.index is None:
            self.summary_label.clear()
            return

        stats = self.index.statistics()
        if not stats['items']:
            self.summary_label.setText(
                "Nothing indexed yet. To search inside file contents, "
                "registry values and archives, run <b>Search index and "
                "indicators</b> from Analysis ▸ Run Analysis Modules.")
            return

        images = len(self.case.evidence()) if self.case else 0
        scope = (f" from {stats['images']} of {images} images"
                 if images > 1 else '')
        self.summary_label.setText(
            f"<b>{stats['items']:,}</b> item(s) indexed{scope}. The emails, "
            f"URLs, numbers and other indicators found are listed in "
            f"Triage ▸ Indicators.")

    # --- searching --------------------------------------------------------

    def _use_example(self, position):
        example = self.examples.itemData(position)
        if example:
            self.query_input.setText(example)
            self.query_input.setFocus()
        self.examples.setCurrentIndex(0)

    def run_search(self):
        if not self.index:
            return
        query = self.query_input.text().strip()
        if not query:
            self.results.setRowCount(0)
            self._set_status()
            self._update_summary()
            return

        try:
            rows = self.index.search(query)
            # The index records an evidence id; the examiner needs its name.
            if self.case:
                names = {e['id']: (e.get('display_name')
                                   or os.path.basename(e['path']))
                         for e in self.case.evidence()}
                for row in rows:
                    row['evidence_name'] = names.get(row.get('evidence_id'), '')
        except SearchError as exc:
            self._set_status(str(exc))
            self.results.setRowCount(0)
            return

        self.results.setRowCount(len(rows))
        for position, row in enumerate(rows):
            excerpt = (row.get('excerpt') or '').replace('\n', ' ').strip()
            size = row.get('size') or 0

            kind = row.get('kind') or 'file'
            if kind == 'archive-member':
                type_text = 'In archive'
            elif row.get('is_deleted'):
                type_text = 'Deleted File'
            else:
                type_text = 'File'

            values = [
                row.get('name') or '',
                excerpt,
                type_text,
                FileSystemUtils.get_readable_size(size) if size else '',
                row.get('created_utc') or '',
                row.get('accessed_utc') or '',
                row.get('mtime_utc') or '',
                row.get('path') or '',
                row.get('evidence_name') or '',
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 0:
                    cell.setData(Qt.UserRole, row)
                    # The same icon the listing gives this file, so a result is
                    # recognisable at a glance rather than a line of text.
                    if self.icon_resolver:
                        name = row.get('name') or ''
                        extension = (name.rsplit('.', 1)[-1].lower()
                                     if '.' in name else 'unknown')
                        cell.setIcon(self.icon_resolver(extension))
                elif column == 1:
                    cell.setToolTip(excerpt)
                self.results.setItem(position, column, cell)

        fit_columns(self.results, {1: 300, 7: 260})
        # Only the result line; the summary of what the index holds stays put.
        self._set_status(
            f"{len(rows):,} result(s) for {query!r}"
            + ("  (showing the first 500)" if len(rows) >= 500 else ''))

    def _context_menu(self, position):
        items = self.results.selectedItems()
        if not items:
            return
        row = self.results.item(items[0].row(), 0).data(Qt.UserRole)
        if row:
            self.result_menu_requested.emit(
                row, self.results.viewport().mapToGlobal(position))

    def _activate(self, _item=None):
        items = self.results.selectedItems()
        if not items:
            return
        row = self.results.item(items[0].row(), 0).data(Qt.UserRole)
        if row:
            self.result_activated.emit(row)

    # --- teardown ---------------------------------------------------------

    def shutdown(self):
        """Close the index before the application closes."""
        if self.index is not None:
            self.index.close()
            self.index = None
