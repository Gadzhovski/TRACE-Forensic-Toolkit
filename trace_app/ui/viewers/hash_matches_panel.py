"""Hash sets: which files matched which set (core/hashsets.py).

A Triage sub-tab. Known bad first, then notable, then known good -- which
is shown only when asked for, because with NSRL linked it is most of the
image and the point of it is not to be read.
"""

import logging
import os
import sqlite3

from PySide6.QtCore import (QAbstractTableModel, QModelIndex,
                            QSortFilterProxyModel, Qt, QThread, QTimer, Signal)
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QPushButton,
                               QTableView, QVBoxLayout, QWidget)

from trace_app.core.case import CASE_DB_NAME, query_hash_matches
from trace_app.core.hashsets import (ALGORITHM_LABELS, CATEGORIES, KNOWN_BAD,
                                     KNOWN_GOOD, NOTABLE)
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.HashMatches')

SHOWN_LIMIT = 50000

_COLUMNS = ('Name', 'Evidence', 'Category', 'Hash set', 'Matched by',
            'Digest', 'Size', 'Path')
_TONE = {KNOWN_BAD: 'malicious', NOTABLE: 'suspicious', KNOWN_GOOD: 'clean'}


class HashMatchWorker(ProcessWorker):
    """Matches a case against its hash sets in a child process."""

    progressed = Signal(int, int, str)
    finished_matching = Signal(int, str)

    kind = 'hashsets'

    def __init__(self, case_folder, library_folder, options, evidence_ids,
                 parent=None):
        super().__init__({'case_folder': case_folder,
                          'library': library_folder, 'options': options,
                          'evidence_ids': evidence_ids}, parent)

    def on_progress(self, done, total, name):
        self.progressed.emit(done, total, name)

    def on_done(self, count, error):
        self.finished_matching.emit(count, error)


class HashMatchModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []
        self.names = {}

    def set_rows(self, rows, names):
        self.beginResetModel()
        self.rows, self.names = rows, names
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(_COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return _COLUMNS[section]
        return None

    def _cell(self, row, column):
        return (row.get('name') or '',
                self.names.get(row.get('evidence_id'), ''),
                CATEGORIES.get(row.get('category'), row.get('category')),
                row.get('set_name') or '',
                ALGORITHM_LABELS.get(row.get('algorithm'),
                                     row.get('algorithm') or ''),
                row.get('digest') or '',
                FileSystemUtils.get_readable_size(row.get('size') or 0),
                ('carved: ' if row.get('origin') == 'carved' else '')
                + (row.get('path') or ''))[column]

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        column = index.column()
        if role == Qt.DisplayRole:
            return self._cell(row, column)
        if role == Qt.ToolTipRole:
            return self._cell(row, column) or None
        if role == Qt.ForegroundRole and column == 2:
            return verdict_brush(_TONE.get(row.get('category'), 'unknown'))
        if role == Qt.UserRole:
            return row
        return None


class _Load(QThread):
    loaded = Signal(int, object)

    def __init__(self, folder, generation, evidence_id, categories, text,
                 parent=None):
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.evidence_id, self.categories, self.text = \
            evidence_id, categories, text

    def run(self):
        rows = []
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True,
                                         timeout=10)
            try:
                rows = query_hash_matches(connection, self.evidence_id,
                                          self.categories, self.text,
                                          SHOWN_LIMIT)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read hash matches: %s", exc)
        self.loaded.emit(self.generation, rows)


class HashMatchesPanel(QWidget):
    file_selected = Signal(dict)
    file_activated = Signal(dict)
    file_menu_requested = Signal(dict, object)
    count_changed = Signal(int)
    manage_requested = Signal()
    match_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("hashMatchesPanel")
        self.case = None
        self.evidence_id = None
        self._names = {}
        self._generation = 0
        self._loads = {}
        self.counts = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)

        row = QHBoxLayout()
        self.status_label = QLabel()
        self.status_label.setObjectName("ntfsStatus")
        self.status_label.setWordWrap(True)
        row.addWidget(self.status_label, 1)
        self.known_good_box = QCheckBox("Show known good")
        self.known_good_box.setObjectName("ntfsRoutine")
        self.known_good_box.setToolTip(
            "List files matching known-good sets (NSRL) too -- usually most "
            "of an operating system.")
        self.known_good_box.toggled.connect(lambda _on: self.refresh())
        row.addWidget(self.known_good_box)
        self.filter_input = QLineEdit()
        self.filter_input.setObjectName("activityFilter")
        self.filter_input.setPlaceholderText("Filter…")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.setMaximumWidth(240)
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(300)
        self._filter_timer.timeout.connect(self.refresh)
        self.filter_input.textChanged.connect(
            lambda _t: self._filter_timer.start())
        row.addWidget(self.filter_input)
        self.match_button = QPushButton("Match Now")
        self.match_button.setObjectName("triageRunButton")
        self.match_button.clicked.connect(self.match_requested.emit)
        row.addWidget(self.match_button)
        self.manage_button = QPushButton("Hash Sets…")
        self.manage_button.setObjectName("triageRunButton")
        self.manage_button.clicked.connect(self.manage_requested.emit)
        row.addWidget(self.manage_button)
        layout.addLayout(row)

        self.model = HashMatchModel(self)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setObjectName("activityTable")
        self.table.setModel(self.proxy)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((220, 130, 100, 180, 90, 270, 80)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().currentRowChanged.connect(
            lambda current, _previous: self._emit(current, self.file_selected))
        self.table.clicked.connect(
            lambda index: self._emit(index, self.file_selected))
        self.table.doubleClicked.connect(
            lambda index: self._emit(index, self.file_activated))
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.table, 1)

    @property
    def loading(self):
        return bool(self._loads)

    @property
    def count(self):
        return self.counts.get(KNOWN_BAD, 0) + self.counts.get(NOTABLE, 0)

    def set_case(self, case):
        self.case = case
        self._names = {}
        if case is not None:
            self._names = {r['id']: r.get('display_name')
                           or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                           for r in case.evidence()}
        self.match_button.setEnabled(case is not None)
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        self.evidence_id = evidence_id
        self.refresh()

    def refresh(self):
        if self.case is None:
            self.counts = {}
            self.model.set_rows([], {})
            self.status_label.setText(
                "Hash sets are matched within a case. Tools ▸ Hash Sets "
                "manages your library.")
            self.count_changed.emit(0)
            return
        try:
            self.counts = self.case.hash_match_counts(self.evidence_id)
        except sqlite3.Error as exc:
            logger.error("Could not count hash matches: %s", exc)
            self.counts = {}
        self.count_changed.emit(self.count)
        categories = [KNOWN_BAD, NOTABLE] + (
            [KNOWN_GOOD] if self.known_good_box.isChecked() else [])
        self._generation += 1
        load = _Load(self.case.folder, self._generation, self.evidence_id,
                     categories, self.filter_input.text().strip(), self)
        load.loaded.connect(self._loaded)
        load.finished.connect(load.deleteLater)
        self._loads[self._generation] = load
        load.start()

    def _loaded(self, generation, rows):
        self._loads.pop(generation, None)
        if generation != self._generation:
            return
        self.model.set_rows(rows, self._names)
        self.table.sortByColumn(-1, Qt.AscendingOrder)
        from trace_app.core import hashsets
        options = hashsets.case_options(self.case)
        bad = self.counts.get(KNOWN_BAD, 0)
        notable = self.counts.get(NOTABLE, 0)
        good = self.counts.get(KNOWN_GOOD, 0)
        if not options.get('enabled'):
            text = ("Hash sets are switched off for this case. Hash Sets… "
                    "turns them on and chooses which to use.")
        elif not (bad or notable or good):
            text = ("No matches recorded. Hash the files (Run Analysis ▸ "
                    "File hashes), then Match Now.")
        else:
            text = (f"{bad:,} known bad, {notable:,} notable, {good:,} known "
                    f"good file(s)")
            if good and not self.known_good_box.isChecked():
                text += " — known good not listed"
            if len(rows) >= SHOWN_LIMIT:
                text += f"; the first {SHOWN_LIMIT:,} shown"
        self.status_label.setText(text)

    def _emit(self, index, signal):
        if index is None or not index.isValid():
            return
        row = self.proxy.data(index, Qt.UserRole)
        if row:
            payload = dict(row, label=f"{row.get('set_name')} match",
                           summary=f"Matches {row.get('set_name')} "
                                   f"({CATEGORIES.get(row.get('category'))})")
            if row.get('origin') == 'carved':
                payload['is_carved'] = True
            signal.emit(payload)

    def _menu(self, point):
        index = self.table.indexAt(point)
        if not index.isValid():
            return
        row = self.proxy.data(index, Qt.UserRole)
        if row:
            self.file_menu_requested.emit(
                dict(row), self.table.viewport().mapToGlobal(point))

    def shutdown(self):
        for load in list(self._loads.values()):
            load.wait(5000)
        self._loads.clear()
