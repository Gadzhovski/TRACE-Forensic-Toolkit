"""The Database tab: a SQLite file's tables, and the records it deleted.

Any SQLite database -- a live file, a deleted one, a carved one, a member
of an archive -- opens here from its bytes (nothing is written out). The
left lists its tables with their row counts and, under each, the records
recovered from where SQLite left them after deleting them
(core/sqlite_recover.py): freelist pages, freeblocks, unused space in
pages, and -- when the database's -wal file is beside it -- older versions
of its pages. Recovery runs on a thread of its own; the tables show at
once.
"""

import logging

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QHeaderView, QLabel,
                               QListWidget, QListWidgetItem, QSplitter,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.DatabaseViewer')

ROWS_SHOWN = 5000
HEADER = b'SQLite format 3\x00'


def _cell_text(value):
    if value is None:
        return ''
    if isinstance(value, bytes):
        return f"<{len(value):,} bytes> {value[:24].hex(' ')}"
    return str(value)


class _Recover(QThread):
    recovered = Signal(int, object, str)

    def __init__(self, generation, data, wal, parent=None):
        super().__init__(parent)
        self.generation, self.data, self.wal = generation, data, wal

    def run(self):
        from trace_app.core import sqlite_recover
        try:
            rows = sqlite_recover.recover(self.data, self.wal)
            self.recovered.emit(self.generation, rows, '')
        except Exception as exc:
            logger.warning("Recovery failed: %s", exc)
            self.recovered.emit(self.generation, [], str(exc))


class DatabaseViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("databaseViewer")
        #: `wal_reader(data)` -> the bytes of the database's -wal, or None.
        self.wal_reader = None
        self._generation = 0
        self._threads = []
        self._db = None
        self._data = None
        self._recovered = {}
        self._wal = None
        self._counts = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        self.info = QLabel()
        self.info.setObjectName("databaseInfo")
        self.info.setWordWrap(True)
        layout.addWidget(self.info)
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)
        self.tables = QListWidget()
        self.tables.setObjectName("databaseTables")
        self.tables.currentItemChanged.connect(self._show)
        splitter.addWidget(self.tables)
        self.grid = QTableWidget()
        self.grid.setObjectName("triageTable")
        self.grid.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.grid.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.grid.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.grid.setItemDelegate(NoFocusDelegate(self.grid))
        self.grid.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        splitter.addWidget(self.grid)
        splitter.setSizes([220, 600])
        self.clear()

    # --- showing a database ------------------------------------------------

    def clear(self):
        self._generation += 1
        self._db = self._data = self._wal = None
        self._recovered = {}
        self._counts = {}
        self.tables.clear()
        self.grid.clear()
        self.grid.setRowCount(0)
        self.grid.setColumnCount(0)
        self.info.setText("Select a SQLite database (browser history, chat "
                          "and app databases) to see its tables and the "
                          "records it deleted.")

    def display(self, content, data):
        self.clear()
        if not content or content[:16] != HEADER:
            self.info.setText("Not a SQLite database.")
            return
        from trace_app.core import sqlite_recover
        from trace_app.core.activity import sqlite_bytes
        wal = None
        if self.wal_reader is not None:
            try:
                wal = self.wal_reader(data)
            except Exception as exc:
                logger.debug("No WAL read: %s", exc)
        self._data, self._wal = content, wal
        try:
            self._db = sqlite_recover.Database(
                sqlite_bytes.apply_wal(content, wal) if wal else content)
        except Exception as exc:
            self.info.setText(f"The database could not be read: {exc}")
            return
        db = self._db
        counts = {}
        try:
            with sqlite_bytes.open_database(content, wal) as connection:
                for table in db.tables:
                    counts[table.name] = connection.execute(
                        f'SELECT count(*) FROM "{table.name}"').fetchone()[0]
        except Exception as exc:
            logger.debug("Row counts failed: %s", exc)
        self._counts = counts
        self.info.setText(
            f"SQLite database: {len(db.tables)} table(s), {db.pages:,} "
            f"pages of {db.page_size:,} bytes, {db.encoding.upper()}"
            + (", with its WAL applied" if wal else '')
            + ". Looking for deleted records…")
        for table in db.tables:
            item = QListWidgetItem(
                f"{table.name} ({counts.get(table.name, 0):,} rows)")
            item.setData(Qt.UserRole, ('table', table.name))
            self.tables.addItem(item)
        if self.tables.count():
            self.tables.setCurrentRow(0)
        thread = _Recover(self._generation, content, wal, self)
        thread.recovered.connect(self._recovered_rows)
        thread.finished.connect(lambda t=thread: self._threads.remove(t)
                                if t in self._threads else None)
        self._threads.append(thread)
        thread.start()

    def _recovered_rows(self, generation, rows, error):
        if generation != self._generation or self._db is None:
            return
        groups = {}
        for row in rows:
            groups.setdefault(row['table'] or '(no table fits)',
                              []).append(row)
        self._recovered = groups
        for name, items in sorted(groups.items()):
            item = QListWidgetItem(f"  {name}: {len(items):,} deleted "
                                   f"record(s) recovered")
            item.setData(Qt.UserRole, ('recovered', name))
            item.setForeground(self.palette().highlight())
            position = next((i + 1 for i in range(self.tables.count())
                             if self.tables.item(i).data(Qt.UserRole) ==
                             ('table', name)), self.tables.count())
            self.tables.insertItem(position, item)
        text = self.info.text().replace(" Looking for deleted records…", '')
        total = len(rows)
        self.info.setText(
            text + (f" {total:,} deleted record(s) recovered." if total else
                    " No deleted records left to recover.")
            + (f" ({error})" if error else ''))

    def _show(self, current, _previous):
        if current is None or self._db is None:
            return
        kind, name = current.data(Qt.UserRole)
        if kind == 'table':
            self._show_table(name)
        else:
            self._show_recovered(self._recovered.get(name, []))

    def _show_table(self, name):
        from trace_app.core.activity import sqlite_bytes
        try:
            with sqlite_bytes.open_database(self._data, self._wal) as db:
                cursor = db.execute(f'SELECT * FROM "{name}" LIMIT '
                                    f'{ROWS_SHOWN}')
                columns = [c[0] for c in cursor.description]
                rows = cursor.fetchall()
        except Exception as exc:
            columns, rows = ['error'], [(str(exc),)]
        self._fill(columns, rows)

    def _show_recovered(self, records):
        width = max((len(r['values']) for r in records), default=0)
        columns = ['Found in', 'Page', 'Note'] + (
            records[0]['columns'] if records and records[0]['table'] else
            [f'column {i + 1}' for i in range(width)])
        rows = [[r['source'], r['page'], r['note']] + list(r['values'])
                for r in records[:ROWS_SHOWN]]
        self._fill(columns, rows)

    def _fill(self, columns, rows):
        grid = self.grid
        grid.clear()
        grid.setColumnCount(len(columns))
        grid.setHorizontalHeaderLabels([str(c) for c in columns])
        grid.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, value in enumerate(row):
                item = QTableWidgetItem(_cell_text(value))
                if isinstance(value, (str, bytes)) and len(value) > 60:
                    item.setToolTip(_cell_text(value)[:2000])
                grid.setItem(r, c, item)
        for c in range(len(columns)):
            grid.setColumnWidth(c, 160)
