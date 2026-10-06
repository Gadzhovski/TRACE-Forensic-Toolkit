"""NTFS: what the file system's own records say (core/ntfs.py).

A Triage sub-tab in three sections:

* Timestomping -- files whose $STANDARD_INFORMATION times were set by hand,
  with both sets of times side by side so the examiner judges for
  themselves. Routine cases (an installer stamping its build date) are
  recorded but shown only when asked for.
* Streams & downloads -- alternate data streams, and Mark of the Web: where a
  downloaded file came from.
* Change journal -- $UsnJrnl, every create, rename and delete it kept.

Rows are read on a thread from a read-only connection, like Activity: a
journal is easily a million records.
"""

import logging
import os
import sqlite3

from PySide6.QtCore import (QAbstractTableModel, QModelIndex,
                            QSortFilterProxyModel, Qt, QThread, QTimer, Signal)
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QMenu,
                               QTabBar, QTableView, QVBoxLayout, QWidget)

from trace_app.core.case import CASE_DB_NAME, ntfs_counts, query_ntfs
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui import icons
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.context_menus import show_menu

logger = logging.getLogger('TRACE.NtfsPanel')

#: Most rows read at once; the filter narrows.
SHOWN_LIMIT = 50000

#: (key, label, icon) of each section, in order.
SECTIONS = (
    ('timestomp', 'Timestomping', icons.FINDING_TIMESTOMP),
    ('streams', 'Streams && downloads', icons.FINDING_STREAM),
    ('slack', 'Index slack', icons.DELETED_FILES),
    ('logfile', '$LogFile', icons.CHANGE_JOURNAL),
    ('journal', 'Change journal', icons.CHANGE_JOURNAL),
)

_COLUMNS = {
    'timestomp': ('Name', 'Evidence', 'Severity', 'Why', 'SI created',
                  'FN created', 'SI modified', 'FN modified', 'Path'),
    'streams': ('Name', 'Evidence', 'Kind', 'Severity', 'Finding',
                'Came from', 'Path'),
    'journal': ('Time (UTC)', 'Evidence', 'Name', 'What happened', 'Path',
                'MFT entry', 'USN'),
    'slack': ('Name', 'Evidence', 'Still listed', 'Created', 'Modified',
              'Size', 'Folder'),
    'logfile': ('LSN', 'Evidence', 'What happened', 'Name', 'Created',
                'Modified', 'Path', 'MFT entry'),
}

_TONE = {'suspicious': 'malicious', 'notable': 'suspicious'}


class NtfsWorker(ProcessWorker):
    """Reads one image's NTFS internals in a child process."""

    progressed = Signal(int, int, str)
    finished_ntfs = Signal(int, str)

    kind = 'ntfs'

    def __init__(self, image_path, case_folder, evidence_id, parent=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id}, parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_ntfs.emit(count, error)


class NtfsModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.section = 'timestomp'
        self.rows = []
        self.names = {}

    def set_rows(self, section, rows, names):
        self.beginResetModel()
        self.section, self.rows, self.names = section, rows, names
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(_COLUMNS[self.section])

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return _COLUMNS[self.section][section]
        if orientation == Qt.Horizontal and role == Qt.ToolTipRole:
            label = _COLUMNS[self.section][section]
            if label.startswith('SI '):
                return ("$STANDARD_INFORMATION: the times Explorer shows, "
                        "which any program can set")
            if label.startswith('FN '):
                return ("$FILE_NAME: the times only the file system "
                        "writes")
        return None

    def _cell(self, row, column):
        evidence = self.names.get(row.get('evidence_id'), '')
        detail = row.get('detail') or {}
        if self.section == 'journal':
            return (row.get('time_utc') or '', evidence, row.get('name') or '',
                    row.get('reasons') or '', row.get('path') or '',
                    f"{row.get('file_entry')}-{row.get('file_sequence')}",
                    str(row.get('usn') or 0))[column]
        if self.section == 'logfile':
            what = {'name added': 'Name added', 'name removed':
                    'Name removed', 'record created': 'Record created',
                    'record freed': 'Record freed'}.get(detail.get('kind'),
                                                        '')
            return (str(detail.get('lsn') or ''), evidence, what,
                    row.get('name') or '', detail.get('created') or '',
                    detail.get('modified') or '', row.get('path') or '',
                    detail.get('MFT entry') or '')[column]
        if self.section == 'slack':
            return (row.get('name') or '', evidence,
                    'yes' if detail.get('still listed') else 'no',
                    detail.get('created') or '', detail.get('modified') or '',
                    f"{row.get('size') or 0:,}",
                    detail.get('folder') or '')[column]
        if self.section == 'timestomp':
            si = detail.get('standard_information') or {}
            fn = detail.get('file_name') or {}
            return (row.get('name') or '', evidence,
                    (row.get('grade') or '').capitalize(),
                    row.get('summary') or '', si.get('created') or '',
                    fn.get('created') or '', si.get('modified') or '',
                    fn.get('modified') or '', row.get('path') or '')[column]
        kind = 'Download' if row.get('kind') == 'motw' else 'Stream'
        source = detail.get('HostUrl') or detail.get('ReferrerUrl') or ''
        return (row.get('name') or '', evidence, kind,
                (row.get('grade') or '').capitalize(),
                row.get('summary') or '', source, row.get('path') or '')[column]

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        column = index.column()
        if role == Qt.DisplayRole:
            return self._cell(row, column)
        if role == Qt.ToolTipRole:
            if self.section == 'timestomp' and column == 3:
                detail = row.get('detail') or {}
                lines = [row.get('summary') or '', '']
                for label, key in (('$STANDARD_INFORMATION',
                                    'standard_information'),
                                   ('$FILE_NAME', 'file_name')):
                    lines.append(label)
                    for name, value in (detail.get(key) or {}).items():
                        lines.append(f"  {name}: {value or '-'}")
                return '\n'.join(lines)
            if self.section == 'streams' and column == 4:
                return '\n'.join(f'{k}: {v}' for k, v in
                                 (row.get('detail') or {}).items())
            return self._cell(row, column) or None
        if role == Qt.ForegroundRole and self.section != 'journal':
            severity_column = {'timestomp': 2, 'slack': 2,
                               'logfile': 2}.get(self.section, 3)
            tone = _TONE.get(row.get('grade'))
            if tone and column in (severity_column, severity_column + 1):
                return verdict_brush(tone)
        if role == Qt.DecorationRole and column == 0 \
                and self.section == 'streams':
            return icons.icon(icons.FINDING_DOWNLOADED
                              if row.get('kind') == 'motw'
                              else icons.FINDING_STREAM)
        if role == Qt.UserRole:
            return row
        return None


class _Load(QThread):
    loaded = Signal(int, object, object)

    def __init__(self, folder, generation, section, evidence_id, text,
                 routine, parent=None):
        super().__init__(parent)
        self.folder, self.generation = folder, generation
        self.section, self.evidence_id = section, evidence_id
        self.text, self.routine = text, routine

    def run(self):
        rows, counts = [], {}
        try:
            path = os.path.join(self.folder, CASE_DB_NAME)
            connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True,
                                         timeout=10)
            try:
                rows = query_ntfs(connection, self.section, self.evidence_id,
                                  self.text, self.routine, SHOWN_LIMIT)
                counts = ntfs_counts(connection, self.evidence_id)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            logger.error("Could not read NTFS results: %s", exc)
        self.loaded.emit(self.generation, rows, counts)


class NtfsPanel(QWidget):
    """The NTFS sub-tab of Triage."""

    file_selected = Signal(dict)
    file_activated = Signal(dict)
    file_menu_requested = Signal(dict, object)
    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ntfsPanel")
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
        self.sections = QTabBar()
        self.sections.setObjectName("activityTabs")
        self.sections.setDocumentMode(True)
        self.sections.setExpanding(False)
        for _key, label, glyph in SECTIONS:
            self.sections.addTab(icons.icon(glyph), label)
        self.sections.currentChanged.connect(lambda _i: self.refresh())
        row.addWidget(self.sections, 1)
        self.routine_box = QCheckBox("Show routine")
        self.routine_box.setObjectName("ntfsRoutine")
        self.routine_box.setToolTip(
            "Also list what NTFS and ordinary software produce every day: "
            "times an installer or archive tool set (earlier than the file "
            "was created, but to the second), and streams Windows writes for "
            "its own reasons.")
        self.routine_box.toggled.connect(lambda _on: self.refresh())
        row.addWidget(self.routine_box)
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

        self.status_label = QLabel()
        self.status_label.setObjectName("ntfsStatus")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.model = NtfsModel(self)
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
        self.table.selectionModel().currentRowChanged.connect(
            lambda current, _previous: self._emit(current, self.file_selected))
        self.table.clicked.connect(
            lambda index: self._emit(index, self.file_selected))
        self.table.doubleClicked.connect(
            lambda index: self._emit(index, self.file_activated))
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.table, 1)

    # --- what to show -----------------------------------------------------

    @property
    def section(self):
        index = self.sections.currentIndex()
        return SECTIONS[index][0] if 0 <= index < len(SECTIONS) else 'timestomp'

    @property
    def loading(self):
        return bool(self._loads)

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

    def show_section(self, key):
        for index, (name, _label, _glyph) in enumerate(SECTIONS):
            if name == key:
                if self.sections.currentIndex() == index:
                    self.refresh()
                self.sections.setCurrentIndex(index)
                return

    def refresh(self):
        if self.case is None:
            self.model.set_rows(self.section, [], {})
            self.status_label.setText("")
            self._set_counts({})
            return
        self._generation += 1
        load = _Load(self.case.folder, self._generation, self.section,
                     self.evidence_id, self.filter_input.text().strip(),
                     self.routine_box.isChecked(), self)
        load.loaded.connect(self._loaded)
        load.finished.connect(load.deleteLater)
        self._loads[self._generation] = load
        load.start()

    def _loaded(self, generation, rows, counts):
        self._loads.pop(generation, None)
        if generation != self._generation:
            return
        section = self.section
        self.model.set_rows(section, rows, self._names)
        widths = {'timestomp': (200, 120, 90, 320, 190, 190, 190, 190),
                  'streams': (220, 120, 90, 90, 320, 300),
                  'slack': (240, 120, 90, 190, 190, 90),
                  'logfile': (110, 120, 130, 220, 190, 190, 360),
                  'journal': (190, 120, 220, 260, 420, 90)}[section]
        for column, width in enumerate(widths):
            self.table.setColumnWidth(column, width)
        if section == 'journal':
            self.table.sortByColumn(0, Qt.DescendingOrder)
        else:
            self.table.sortByColumn(-1, Qt.AscendingOrder)
        self._set_counts(counts)
        self.status_label.setText(self._status(section, rows, counts))

    def _status(self, section, rows, counts):
        if not counts.get('journal') and not any(
                counts.get(k) for k in ('timestomp', 'streams', 'slack',
                                        'logfile',
                                        'routine_timestomp',
                                        'routine_streams',
                                        'routine_slack')):
            return ("Nothing read yet. Run Analysis with \"NTFS: $MFT times, "
                    "change journal and streams\" to read each NTFS volume's "
                    "own records.")
        more = (f" — the first {SHOWN_LIMIT:,} shown; filter to narrow"
                if len(rows) >= SHOWN_LIMIT else '')
        if section == 'journal':
            return (f"{len(rows):,} change-journal record(s){more}. Each is "
                    "something NTFS recorded happening to a file — including "
                    "files no longer on the volume.")
        routine = counts.get(f'routine_{section}', 0)
        hidden = (f" {routine:,} routine one(s) hidden — tick Show routine."
                  if routine and not self.routine_box.isChecked() else '')
        if section == 'timestomp':
            return (f"{len(rows):,} file(s){more}. Hover Why for both sets "
                    f"of times.{hidden}")
        if section == 'logfile':
            return (f"{len(rows):,} operation(s) from $LogFile{more}, "
                    f"newest first -- files created, named, unnamed and "
                    f"freed. The log keeps no time of its own; the times "
                    f"shown are its $FILE_NAME copies'.")
        if section == 'slack':
            return (f"{len(rows):,} name(s) left in folders' $I30 index "
                    f"slack{more} -- files deleted, renamed or moved away, "
                    f"with their times.{hidden}")
        return f"{len(rows):,} stream(s) and download(s){more}.{hidden}"

    def _set_counts(self, counts):
        self.counts = counts or {}
        for index, (key, label, _glyph) in enumerate(SECTIONS):
            count = self.counts.get(key, 0)
            self.sections.setTabText(index, f"{label} ({count:,})")
        self.count_changed.emit(self.count)

    @property
    def count(self):
        return sum(self.counts.get(k, 0) for k in ('timestomp', 'streams',
                                                    'slack'))

    # --- actions ----------------------------------------------------------

    def _payload(self, index):
        if index is None or not index.isValid():
            return None
        row = self.proxy.data(index, Qt.UserRole)
        if not row:
            return None
        payload = dict(row)
        if self.section == 'journal':
            payload.setdefault('summary', row.get('reasons'))
        payload.setdefault('label', payload.get('summary') or 'NTFS')
        return payload

    def _emit(self, index, signal):
        payload = self._payload(index)
        if payload:
            signal.emit(payload)

    def _menu(self, point):
        index = self.table.indexAt(point)
        payload = self._payload(index)
        if not payload:
            return
        if self.section != 'journal':
            self.file_menu_requested.emit(
                payload, self.table.viewport().mapToGlobal(point))
            return
        menu = QMenu(self)
        copy_path = menu.addAction("Copy Path")
        copy_row = menu.addAction("Copy Row")
        menu.addSeparator()
        show = menu.addAction("Show File in Listing")
        chosen = show_menu(menu, self.table.viewport().mapToGlobal(point))
        if chosen == copy_path:
            QGuiApplication.clipboard().setText(payload.get('path') or '')
        elif chosen == copy_row:
            QGuiApplication.clipboard().setText('\t'.join(
                self.model._cell(payload, c) for c in range(
                    len(_COLUMNS['journal']))))
        elif chosen == show:
            self.file_activated.emit(payload)

    def shutdown(self):
        for load in list(self._loads.values()):
            load.wait(5000)
        self._loads.clear()

