"""Universal search: one place to ask a question of the whole case.

This replaces a search that matched filenames and nothing else. It looks in
file contents, paths, registry values and archive members, and it answers
questions about entities -- every email address, every URL, every IP -- which
full-text search answers badly.

Results appear here rather than in the listing table. Overloading the listing
meant search and browsing fought over the same widget: columns were toggled,
browse state was saved and restored, and returning from a search was a mode
change. A separate tab leaves the listing alone.
"""

import logging
import os

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QProgressBar,
                               QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from trace_app.core.image_handler import ImageHandler
from trace_app.core.indexer import index_evidence
from trace_app.core.search_index import (INDEX_DONE, SearchError, SearchIndex)
from trace_app.infra.constants import CONTROL_HEIGHT, TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui.dialogs import message
from trace_app.ui.widgets.table_columns import fit_columns

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
    ('Every email address', 'email:'),
    ('Every URL', 'url:'),
    ('Every domain', 'domain:'),
    ('Every IPv4 address', 'ip:'),
    ('Every IPv6 address', 'ipv6:'),
    ('Private IPv4 ranges', '/\\b(?:10\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.)\\d{1,3}\\.\\d{1,3}\\b/'),
    ('MAC addresses', '/\\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\\b/'),
    ('UK phone numbers', '/\\b(?:0|\\+?44\\s?)(?:\\d\\s?){9,10}\\b/'),
    ('US phone numbers', '/\\b(?:\\+?1[\\s.-]?)?\\(?\\d{3}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4}\\b/'),

    ('— Financial —', ''),
    ('Credit card numbers', '/\\b(?:4\\d{12}(?:\\d{3})?|5[1-5]\\d{14}|3[47]\\d{13}|6(?:011|5\\d{2})\\d{12})\\b/'),
    ('IBAN', '/\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b/'),
    ('Bitcoin addresses', 'btc:'),
    ('Currency amounts', '/[£$€]\\s?\\d[\\d,]*(?:\\.\\d{2})?/'),

    ('— Identifiers —', ''),
    ('A known hash', 'hash:d41d8cd98f00b204e9800998ecf8427e'),
    ('Every hash-like string', 'hash:'),
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


class IndexWorker(QThread):
    """Runs the indexer off the UI thread."""

    progressed = Signal(int, int, str)
    finished_indexing = Signal(int, str)

    def __init__(self, image_path, case_folder, evidence_id, parent=None):
        super().__init__(parent)
        # Paths, not open objects. A SQLite connection belongs to the thread
        # that created it, and pytsk3's image handle is no better: an
        # ImageHandler opened by the UI thread reports N/A for every volume
        # when read from here, so indexing walked nothing and reported
        # success. The worker opens its own of each.
        self.image_path = image_path
        self.case_folder = case_folder
        self.evidence_id = evidence_id
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        index = None
        handler = None
        try:
            index = SearchIndex(self.case_folder)
            handler = ImageHandler(self.image_path)
            if not handler.load_image():
                raise RuntimeError(
                    f"Could not open {self.image_path} for indexing.")
            count = index_evidence(
                handler, index, self.evidence_id,
                progress=lambda done, total, path:
                    self.progressed.emit(done, total, path),
                should_stop=lambda: self._stop)
            self.finished_indexing.emit(count, '')
        except Exception as exc:
            logger.error("Indexing failed: %s", exc)
            self.finished_indexing.emit(0, str(exc))
        finally:
            if index is not None:
                index.close()
            if handler is not None:
                try:
                    handler.close_resources()
                except Exception:
                    pass


class SearchPanel(QWidget):
    """Query the case index, and jump from a result to its evidence."""

    #: Emitted with a result row when the user opens one.
    result_activated = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self.index = None
        self.image_handler = None
        self._worker = None
        #: Resolves an extension to the icon the listing would use. Injected
        #: by the host so this panel does not reach into a DatabaseManager.
        self.icon_resolver = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

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

        # --- index row ---
        index_row = QHBoxLayout()
        index_row.setSpacing(6)

        self.status_label = QLabel()
        self.status_label.setObjectName("searchStatus")
        self.status_label.setWordWrap(True)
        index_row.addWidget(self.status_label, 1)

        self.index_button = QPushButton("Build Index")
        self.index_button.setFixedHeight(CONTROL_HEIGHT)
        self.index_button.clicked.connect(self.toggle_indexing)
        index_row.addWidget(self.index_button)
        layout.addLayout(index_row)

        self.progress = QProgressBar()
        self.progress.setObjectName("searchProgress")
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

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

    def set_image_handler(self, image_handler):
        self.image_handler = image_handler
        self._update_status()

    def _update_status(self):
        has_case = self.case is not None and self.index is not None
        self.query_input.setEnabled(has_case)
        self.search_button.setEnabled(has_case)
        self.index_button.setEnabled(has_case and self.image_handler is not None)

        if not has_case:
            self.status_label.setText(
                "Quick triage — universal search needs a case, because the "
                "index is kept with it. File ▸ New Case starts one.")
            return

        stats = self.index.statistics()
        if not stats['items']:
            self.status_label.setText(
                "Nothing indexed yet. Build the index to search inside file "
                "contents, registry values and archives.")
            return

        entities = ', '.join(
            f"{count} {kind}" for kind, count in
            sorted(stats['entities'].items()) if count)
        self.status_label.setText(
            f"{stats['items']:,} item(s) indexed"
            + (f" — {entities}" if entities else ''))

    # --- indexing ---------------------------------------------------------

    def toggle_indexing(self):
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self.index_button.setText("Stopping…")
            self.index_button.setEnabled(False)
            return
        self.start_indexing()

    def start_indexing(self):
        if not (self.case and self.index and self.image_handler):
            return

        path = getattr(self.image_handler, 'image_path', None)
        row = self.case.evidence_for_path(path) if path else None
        evidence_id = row['id'] if row else self.case.add_evidence(path)

        self._worker = IndexWorker(path, self.case.folder, evidence_id, self)
        self._worker.progressed.connect(self._on_progress)
        self._worker.finished_indexing.connect(self._on_indexed)
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.index_button.setText("Stop")
        self._worker.start()

    def _on_progress(self, done, total, path):
        if total:
            self.progress.setMaximum(total)
            self.progress.setValue(done)
        self.status_label.setText(f"Indexing {done:,} of {total:,} — {path}")

    def _on_indexed(self, count, error):
        self.progress.setVisible(False)
        self.index_button.setText("Rebuild Index")
        self.index_button.setEnabled(True)
        if error:
            message.warning(self, "Indexing failed", error)

        # Reopen this thread's connection: the worker wrote through its own,
        # and a connection opened before those writes does not see them.
        if self.case is not None:
            try:
                if self.index is not None:
                    self.index.close()
                self.index = SearchIndex(self.case.folder)
            except Exception as exc:
                logger.error("Could not reopen the search index: %s", exc)

        self._update_status()

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
            self._update_status()
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
            self.status_label.setText(str(exc))
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
        self.status_label.setText(
            f"{len(rows):,} result(s) for {query!r}"
            + ("  (showing the first 500)" if len(rows) >= 500 else ''))

    def _activate(self, _item=None):
        items = self.results.selectedItems()
        if not items:
            return
        row = self.results.item(items[0].row(), 0).data(Qt.UserRole)
        if row:
            self.result_activated.emit(row)

    # --- teardown ---------------------------------------------------------

    def shutdown(self):
        """Stop any running index before the application closes."""
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(3000)
        if self.index is not None:
            self.index.close()
            self.index = None
