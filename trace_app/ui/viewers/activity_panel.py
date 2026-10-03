"""Activity: what the people using each device did.

A top-level tab beside Triage. Sub-tabs follow core/activity's categories --
programs run, files and folders, USB devices, the Recycle Bin, logons and
remote access, web history, downloads and searches -- with "All" first, every
record in time order: the beginnings of a timeline. Every row names the file
it was read from; landing on it previews that file, double-click goes to it.

A model-based view: a busy machine's browser history alone is tens of
thousands of rows, and building a QTableWidgetItem per cell for that is
seconds of frozen window. Rows are read on a thread of their own, from a
read-only connection to the case database.
"""

import json
import logging
import os
import sqlite3

from PySide6.QtCore import (QAbstractTableModel, QModelIndex,
                            QSortFilterProxyModel, Qt, QThread, QTimer, Signal)
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QMenu,
                               QPushButton, QSizePolicy, QTabBar, QTableView,
                               QToolBar, QVBoxLayout, QWidget)

from trace_app.core.activity import CATEGORIES
from trace_app.core.case import CASE_DB_NAME, query_user_activity
from trace_app.infra.constants import PANEL_ICON_SIZE, TABLE_ROW_HEIGHT
from trace_app.ui import icons
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.widgets.toolbars import prepare_toolbar

logger = logging.getLogger('TRACE.ActivityPanel')

#: Most rows read at once; the text filter and the categories narrow it.
SHOWN_LIMIT = 50000

_COLUMNS = ('Time', 'What', 'Subject', 'User', 'Details', 'Source',
            'Evidence')


class ActivityWorker(ProcessWorker):
    """Reads one image's activity in a child process (core/background.py)."""

    progressed = Signal(int, int, str)
    finished_activity = Signal(int, str)

    kind = 'activity'

    def __init__(self, image_path, case_folder, evidence_id, parent=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id}, parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_activity.emit(count, error)


def detail_text(detail, limit=None):
    """'key: value; key: value' -- one line for the table."""
    parts = [f'{key}: {value}' for key, value in (detail or {}).items()
             if key != 'basis']
    text = '; '.join(parts)
    return text if limit is None or len(text) <= limit else \
        text[:limit - 1] + '…'


class ActivityModel(QAbstractTableModel):
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
        if column == 0:
            time = row.get('time_utc') or ''
            return f'{time} (local)' if time and row.get('time_local') \
                else time
        if column == 1:
            return row.get('what') or ''
        if column == 2:
            return row.get('subject') or ''
        if column == 3:
            return row.get('user') or ''
        if column == 4:
            return detail_text(row.get('detail'), 300)
        if column == 5:
            return row.get('source') or ''
        if column == 6:
            return self.names.get(row.get('evidence_id'), '')
        return ''

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        column = index.column()
        if role == Qt.DisplayRole:
            return self._cell(row, column)
        if role == Qt.ToolTipRole:
            if column == 0 and row.get('time_local'):
                return ("Local time of the machine that wrote it; the source "
                        "keeps no time zone.")
            if column == 0 and not row.get('time_utc'):
                return "The source keeps no time for this entry."
            if column == 4:
                lines = [f'{k}: {v}' for k, v in
                         (row.get('detail') or {}).items()]
                return '\n'.join(lines) or None
            if column == 5:
                return row.get('source_path') or None
            return self._cell(row, column) or None
        if role == Qt.UserRole:
            return row
        return None


class _Load(QThread):
    """One read of the case's activity, with its own read-only connection."""

    loaded = Signal(int, object)

    def __init__(self, folder, generation, evidence_id, category, text,
                 parent=None):
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.evidence_id, self.category, self.text = evidence_id, category, text

    def run(self):
        rows = []
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = sqlite3.connect(
                f'file:{path}?mode=ro', uri=True, timeout=10)
            try:
                rows = query_user_activity(connection, self.evidence_id,
                                           self.category, self.text,
                                           limit=SHOWN_LIMIT)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read activity: %s", exc)
        self.loaded.emit(self.generation, rows)


class ActivityPanel(QWidget):
    """The Activity tab."""

    row_selected = Signal(dict)
    row_activated = Signal(dict)
    row_menu_requested = Signal(dict, object)
    run_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("activityPanel")
        self.case = None
        self.evidence_id = None
        self.category = None
        self._names = {}
        self._generation = 0
        self._loads = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.toolbar = QToolBar()
        prepare_toolbar(self.toolbar)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        icon_label = QLabel()
        icon_label.setObjectName("panelIcon")
        icons.apply_pixmap(icon_label, icons.ACTIVITY, PANEL_ICON_SIZE)
        self.toolbar.addWidget(icon_label)
        title = QLabel("Activity")
        title.setObjectName("panelTitle")
        self.toolbar.addWidget(title)
        self.status_label = QLabel()
        self.status_label.setObjectName("triageStatus")
        self.status_label.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Preferred)
        self.toolbar.addWidget(self.status_label)
        self.evidence_filter = QComboBox()
        self.evidence_filter.setObjectName("triageEvidenceFilter")
        self.evidence_filter.setToolTip("Show activity from every image in "
                                        "the case, or from one.")
        self.evidence_filter.currentIndexChanged.connect(self._filter_changed)
        self.toolbar.addWidget(self.evidence_filter)
        self.run_button = QPushButton("Read Activity")
        self.run_button.setObjectName("triageRunButton")
        self.run_button.setToolTip("Analysis ▸ Run Analysis Modules, with "
                                   "Windows activity and browser history")
        self.run_button.clicked.connect(self.run_requested.emit)
        self.toolbar.addWidget(self.run_button)
        outer.addWidget(self.toolbar)

        layout = QVBoxLayout()
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(4)
        outer.addLayout(layout)

        row = QHBoxLayout()
        self.tabs = QTabBar()
        self.tabs.setObjectName("activityTabs")
        self.tabs.setDocumentMode(True)
        self.tabs.setExpanding(False)
        self._keys = [None] + [key for key, _label in CATEGORIES]
        self._labels = ['All'] + [label for _key, label in CATEGORIES]
        for key, label in zip(self._keys, self._labels):
            self.tabs.addTab(icons.icon(icons.ACTIVITY_CATEGORIES[key]),
                             label)
        self.tabs.currentChanged.connect(self._tab_changed)
        row.addWidget(self.tabs, 1)
        self.filter_input = QLineEdit()
        self.filter_input.setObjectName("activityFilter")
        self.filter_input.setPlaceholderText("Filter…")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.setMaximumWidth(260)
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(300)
        self._filter_timer.timeout.connect(self.refresh)
        self.filter_input.textChanged.connect(
            lambda _t: self._filter_timer.start())
        row.addWidget(self.filter_input)
        layout.addLayout(row)

        self.model = ActivityModel(self)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setObjectName("activityTable")
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.DescendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((150, 190, 420, 110, 320, 140, 140)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().currentRowChanged.connect(
            lambda current, _previous: self._emit(current, self.row_selected))
        self.table.clicked.connect(
            lambda index: self._emit(index, self.row_selected))
        self.table.doubleClicked.connect(
            lambda index: self._emit(index, self.row_activated))
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.table, 1)

        self.set_case(None)

    # --- what to show -----------------------------------------------------

    def set_case(self, case):
        self.case = case
        self._names = {}
        if case is not None:
            self._names = {r['id']: r.get('display_name')
                           or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                           for r in case.evidence()}
        self.evidence_filter.blockSignals(True)
        self.evidence_filter.clear()
        self.evidence_filter.addItem("All evidence", None)
        for evidence_id, name in sorted(self._names.items(),
                                        key=lambda kv: kv[1].lower()):
            self.evidence_filter.addItem(name, evidence_id)
        index = self.evidence_filter.findData(self.evidence_id)
        self.evidence_filter.setCurrentIndex(index if index >= 0 else 0)
        self.evidence_id = self.evidence_filter.currentData()
        self.evidence_filter.blockSignals(False)
        self.evidence_filter.setVisible(len(self._names) > 1)
        self.run_button.setEnabled(case is not None)
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        index = self.evidence_filter.findData(evidence_id)
        self.evidence_filter.setCurrentIndex(index if index >= 0 else 0)

    def show_category(self, category):
        """Bring a category's sub-tab forward ('programs', ... or None)."""
        index = self._keys.index(category) if category in self._keys else 0
        if self.tabs.currentIndex() == index:
            self.refresh()
        self.tabs.setCurrentIndex(index)

    @property
    def loading(self):
        return bool(self._loads)

    def _filter_changed(self, _index):
        self.evidence_id = self.evidence_filter.currentData()
        self.refresh()

    def _tab_changed(self, index):
        self.category = self._keys[index] if 0 <= index < len(self._keys) \
            else None
        self.refresh()

    def refresh(self):
        """Reload the counts and the rows (rows on a thread)."""
        self._update_counts()
        if self.case is None:
            self.model.set_rows([], {})
            self.status_label.setText("Activity is kept with a case. "
                                      "File ▸ New Case starts one.")
            return
        self._generation += 1
        load = _Load(self.case.folder, self._generation, self.evidence_id,
                     self.category, self.filter_input.text().strip(), self)
        load.loaded.connect(self._loaded)
        load.finished.connect(load.deleteLater)
        self._loads[self._generation] = load
        self.status_label.setText("Loading…")
        load.start()

    def _loaded(self, generation, rows):
        self._loads.pop(generation, None)
        if generation != self._generation:
            return
        self.model.set_rows(rows, self._names)
        self.table.sortByColumn(self.table.horizontalHeader()
                                .sortIndicatorSection(),
                                self.table.horizontalHeader()
                                .sortIndicatorOrder())
        if rows:
            more = (f" — the newest {SHOWN_LIMIT:,} shown; filter to narrow"
                    if len(rows) >= SHOWN_LIMIT else '')
            self.status_label.setText(f"{len(rows):,} record(s){more}")
        elif self._summary:
            self.status_label.setText("Nothing matches.")
        else:
            self.status_label.setText(
                "Nothing read yet. Read Activity runs Windows activity and "
                "browser history from Analysis ▸ Run Analysis Modules.")

    def _update_counts(self):
        self._summary = {}
        if self.case is not None:
            try:
                self._summary = self.case.user_activity_summary(
                    self.evidence_id)
            except sqlite3.Error as exc:
                logger.error("Could not count activity: %s", exc)
        total = sum(self._summary.values())
        for index, key in enumerate(self._keys):
            count = total if key is None else self._summary.get(key, 0)
            self.tabs.setTabText(index, f"{self._labels[index]} ({count:,})")

    @property
    def count(self):
        return sum(getattr(self, '_summary', {}).values())

    # --- actions ----------------------------------------------------------

    def _emit(self, index, signal):
        if index is None or not index.isValid():
            return
        row = self.proxy.data(index, Qt.UserRole)
        if row:
            signal.emit(row)

    def _menu(self, point):
        index = self.table.indexAt(point)
        if not index.isValid():
            return
        row = self.proxy.data(index, Qt.UserRole)
        menu = QMenu(self)
        copy_subject = menu.addAction("Copy Subject")
        copy_row = menu.addAction("Copy Row")
        menu.addSeparator()
        source = menu.addAction("Show Source File in Listing")
        source.setEnabled(bool(row.get('source_ref')))
        chosen = menu.exec_(self.table.viewport().mapToGlobal(point))
        if chosen == copy_subject:
            QGuiApplication.clipboard().setText(row.get('subject') or '')
        elif chosen == copy_row:
            QGuiApplication.clipboard().setText('\t'.join([
                row.get('time_utc') or '', row.get('what') or '',
                row.get('subject') or '', row.get('user') or '',
                json.dumps(row.get('detail') or {}, ensure_ascii=False),
                row.get('source') or '', row.get('source_path') or '']))
        elif chosen == source:
            self.row_activated.emit(row)

    def shutdown(self):
        for load in list(self._loads.values()):
            load.wait(5000)
        self._loads.clear()
