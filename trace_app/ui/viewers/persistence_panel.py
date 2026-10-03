"""Persistence: everything set to start by itself (core/persistence.py).

A Triage sub-tab. Suspicious and notable entries first, each with why;
routine ones (Windows' own services, signed per-user updaters) only when
asked for. A row previews the file the entry starts -- or, when that file
is not on the image, the hive or task file the entry was read from.
"""

import logging
import os
import sqlite3

from PySide6.QtCore import (QAbstractTableModel, QModelIndex,
                            QSortFilterProxyModel, Qt, QThread, QTimer, Signal)
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QTableView,
                               QVBoxLayout, QWidget)

from trace_app.core.case import CASE_DB_NAME, query_persistence
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.PersistencePanel')

_COLUMNS = ('Severity', 'Where', 'Name', 'Starts', 'Why', 'File on image',
            'Signed', 'User', 'Evidence', 'Read from')
_TONE = {'suspicious': 'malicious', 'notable': 'suspicious'}


class PersistenceWorker(ProcessWorker):
    progressed = Signal(int, int, str)
    finished_persistence = Signal(int, str)

    kind = 'persistence'

    def __init__(self, image_path, case_folder, evidence_id, library_folder,
                 parent=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id,
                          'hash_library': library_folder}, parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_persistence.emit(count, error)


def _flag(value, yes, no, unknown=''):
    return unknown if value is None else (yes if value else no)


class PersistenceModel(QAbstractTableModel):
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

    def cell(self, row, column):
        hash_note = f" ({row['hash_category']})" if row.get(
            'hash_category') else ''
        return (
            (row.get('grade') or '').capitalize(), row.get('location') or '',
            row.get('name') or '', row.get('command') or '',
            '; '.join(row.get('reasons') or []),
            _flag(row.get('target_exists'), 'present', 'missing') + hash_note,
            _flag(row.get('signed'), 'embedded', 'none', ''),
            row.get('user') or '',
            self.names.get(row.get('evidence_id'), ''),
            (row.get('source') or '').rsplit('/', 1)[-1])[column]

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        column = index.column()
        if role == Qt.DisplayRole:
            return self.cell(row, column)
        if role == Qt.ToolTipRole:
            if column == 4:
                return '\n'.join(row.get('reasons') or []) or None
            if column == 3:
                lines = [row.get('command') or '',
                         f"Target: {row.get('target') or '?'}"]
                lines += [f"{k}: {v}" for k, v in
                          (row.get('detail') or {}).items()]
                return '\n'.join(lines)
            if column == 6:
                return ("An Authenticode signature embedded in the file. "
                        "Present or not -- never verified; Windows' own "
                        "files are often signed in a catalog instead.")
            if column == 9:
                return row.get('source') or None
            return self.cell(row, column) or None
        if role == Qt.ForegroundRole and column in (0, 4):
            tone = _TONE.get(row.get('grade'))
            return verdict_brush(tone) if tone else None
        if role == Qt.UserRole:
            return row
        return None


class _Load(QThread):
    loaded = Signal(int, object, object)

    def __init__(self, folder, generation, evidence_id, routine, text,
                 parent=None):
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.evidence_id, self.routine, self.text = evidence_id, routine, text

    def run(self):
        rows, counts = [], {}
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True,
                                         timeout=10)
            try:
                rows = query_persistence(connection, self.evidence_id,
                                         self.routine, self.text)
                where = ('', []) if self.evidence_id is None else (
                    " WHERE evidence_id = ?", [self.evidence_id])
                counts = {grade: count for grade, count in connection.execute(
                    "SELECT grade, COUNT(*) FROM persistence" + where[0]
                    + " GROUP BY grade", where[1])}
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read persistence: %s", exc)
        self.loaded.emit(self.generation, rows, counts)


class PersistencePanel(QWidget):
    file_selected = Signal(dict)
    file_activated = Signal(dict)
    file_menu_requested = Signal(dict, object)
    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("persistencePanel")
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
        self.routine_box = QCheckBox("Show routine")
        self.routine_box.setObjectName("ntfsRoutine")
        self.routine_box.setToolTip("Also list Windows' own services and "
                                    "drivers and the ordinary autostarts")
        self.routine_box.toggled.connect(lambda _on: self.refresh())
        row.addWidget(self.routine_box)
        self.filter_input = QLineEdit()
        self.filter_input.setObjectName("activityFilter")
        self.filter_input.setPlaceholderText("Filter…")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.setFixedWidth(220)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(300)
        self._timer.timeout.connect(self.refresh)
        self.filter_input.textChanged.connect(lambda _t: self._timer.start())
        row.addWidget(self.filter_input)
        layout.addLayout(row)

        self.model = PersistenceModel(self)
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
        for column, width in enumerate((90, 150, 180, 340, 320, 110, 80,
                                        100, 120)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().currentRowChanged.connect(
            lambda current, _previous: self._emit(current,
                                                  self.file_selected))
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
        return self.counts.get('suspicious', 0) + self.counts.get('notable', 0)

    def set_case(self, case):
        self.case = case
        self._names = {}
        if case is not None:
            self._names = {r['id']: r.get('display_name')
                           or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                           for r in case.evidence()}
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        self.evidence_id = evidence_id
        self.refresh()

    def refresh(self):
        if self.case is None:
            self.model.set_rows([], {})
            self.counts = {}
            self.count_changed.emit(0)
            self.status_label.setText('')
            return
        self._generation += 1
        load = _Load(self.case.folder, self._generation, self.evidence_id,
                     self.routine_box.isChecked(),
                     self.filter_input.text().strip(), self)
        load.loaded.connect(self._loaded)
        load.finished.connect(load.deleteLater)
        self._loads[self._generation] = load
        load.start()

    def _loaded(self, generation, rows, counts):
        self._loads.pop(generation, None)
        if generation != self._generation:
            return
        self.counts = counts
        self.model.set_rows(rows, self._names)
        self.table.sortByColumn(-1, Qt.AscendingOrder)
        self.count_changed.emit(self.count)
        total = sum(counts.values())
        if not total:
            self.status_label.setText(
                "Nothing read yet. Run Analysis with \"Persistence "
                "(autoruns)\" to list everything set to start by itself.")
            return
        routine = counts.get('benign', 0)
        text = (f"{counts.get('suspicious', 0)} suspicious, "
                f"{counts.get('notable', 0)} notable, {routine} routine "
                f"autostart(s)")
        if routine and not self.routine_box.isChecked():
            text += " — routine ones hidden"
        self.status_label.setText(text + ". Hover Why for the reasons.")

    def _payload(self, row):
        """What preview/open take: the file started, else where it came
        from."""
        if row.get('target_ref'):
            ref, path = row['target_ref'], row.get('target') or ''
        else:
            ref, path = row.get('source_ref'), row.get('source') or ''
        return {'artifact_ref': ref, 'evidence_id': row.get('evidence_id'),
                'name': path.replace('\\', '/').rsplit('/', 1)[-1],
                'path': path, 'label': f"{row['location']}: {row['name']}",
                'summary': '; '.join(row.get('reasons') or [])}

    def _emit(self, index, signal):
        if index is None or not index.isValid():
            return
        row = self.proxy.data(index, Qt.UserRole)
        if row and (row.get('target_ref') or row.get('source_ref')):
            signal.emit(self._payload(row))

    def _menu(self, point):
        index = self.table.indexAt(point)
        if not index.isValid():
            return
        row = self.proxy.data(index, Qt.UserRole)
        if row:
            self.file_menu_requested.emit(
                self._payload(row), self.table.viewport().mapToGlobal(point))

    def shutdown(self):
        for load in list(self._loads.values()):
            load.wait(5000)
        self._loads.clear()
