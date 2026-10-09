"""A SQLite file's tables, and the records it deleted.

The Application tab's view of a SQLite database (core/filetypes recognises
one by its header, whatever it is called): a live file, a deleted one, a
carved one, a member of an archive -- opened from its bytes (nothing is
written out). It was a tab of its own, empty for every other file and easy
to miss for a database. The
left lists its tables with their row counts and, under each, the records
recovered from where SQLite left them after deleting them
(core/sqlite_recover.py): freelist pages, freeblocks, unused space in
pages, and -- when the database's -wal file is beside it -- older versions
of its pages. Recovery runs on a thread of its own; the tables show at
once.

A binary cell -- a BLOB, or TEXT that is not text (SQLite stores whatever
it is given) -- says what it holds ('SQLite database, 110,592 bytes') and
is a file of its own: right-click opens it in the viewer (a database
inside a database, a picture, a plist), exports it (hashed, checked,
audited: core/evidence_export.py) or copies it as hex.
"""

import logging
import os

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QFileDialog,
                               QHeaderView, QLabel, QListWidget,
                               QListWidgetItem, QMenu, QSplitter,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.DatabaseViewer')


def _safe(label):
    from trace_app.core.evidence_export import safe_component
    return safe_component(label.replace(' > ', '_'), 'cell')

ROWS_SHOWN = 5000
HEADER = b'SQLite format 3\x00'


#: What a binary cell holds, from its first bytes.
_BLOB_KINDS = ((b'SQLite format 3\x00', 'SQLite database'),
               (b'bplist00', 'binary plist'), (b'\xff\xd8\xff', 'JPEG'),
               (b'\x89PNG\r\n\x1a\n', 'PNG'), (b'GIF8', 'GIF'),
               (b'%PDF', 'PDF'), (b'PK\x03\x04', 'ZIP'),
               (b'\x1f\x8b', 'gzip'), (b'<?xml', 'XML'),
               (b'\xd0\xcf\x11\xe0', 'OLE (Office, Thumbs.db)'),
               (b'RIFF', 'RIFF (WebP, WAV, AVI)'), (b'MZ', 'Windows program'))


def blob_kind(value):
    """'SQLite database', 'JPEG'... or 'binary' for a cell's bytes."""
    for magic, name in _BLOB_KINDS:
        if value.startswith(magic):
            return name
    if value[4:8] == b'ftyp':
        return 'MP4 / HEIC'
    return 'binary'


def _cell_text(value):
    if value is None:
        return ''
    if isinstance(value, bytes):
        return (f"<{blob_kind(value)}, {len(value):,} bytes> "
                f"{value[:16].hex(' ')}")
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
        #: `blob_opener(content, label)`: show a cell's bytes as a file.
        self.blob_opener = None
        self._source = {}
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
        self.grid.setContextMenuPolicy(Qt.CustomContextMenu)
        self.grid.customContextMenuRequested.connect(self._cell_menu)
        self.grid.cellDoubleClicked.connect(self._open_cell)
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
        self._source = dict(data or {})
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
            # Exact: TEXT that is not UTF-8 comes back as its bytes, to be
            # opened as the file it is, not decoded into nonsense.
            with sqlite_bytes.open_database(self._data, self._wal,
                                            exact=True) as db:
                cursor = db.execute(f'SELECT * FROM "{name}" LIMIT '
                                    f'{ROWS_SHOWN}')
                columns = [c[0] for c in cursor.description]
                rows = cursor.fetchall()
        except Exception as exc:
            columns, rows = ['error'], [(str(exc),)]
        self._table = name
        self._fill(columns, rows)

    def _show_recovered(self, records):
        width = max((len(r['values']) for r in records), default=0)
        columns = ['Found in', 'Page', 'Note'] + (
            records[0]['columns'] if records and records[0]['table'] else
            [f'column {i + 1}' for i in range(width)])
        rows = [[r['source'], r['page'], r['note']] + list(r['values'])
                for r in records[:ROWS_SHOWN]]
        self._table = f"{records[0]['table']} (recovered)" if records \
            else 'recovered'
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
                if isinstance(value, bytes):
                    # The bytes themselves, for Open / Export / Copy.
                    item.setData(Qt.UserRole, bytes(value))
                    item.setToolTip("Right-click (or double-click) to open "
                                    "these bytes as a file, or export them")
                elif isinstance(value, str) and len(value) > 60:
                    item.setToolTip(_cell_text(value)[:2000])
                grid.setItem(r, c, item)
        for c in range(len(columns)):
            grid.setColumnWidth(c, 160)

    # --- a cell's bytes as a file --------------------------------------------

    def cell_bytes(self, row, column):
        item = self.grid.item(row, column)
        value = item.data(Qt.UserRole) if item is not None else None
        return value if isinstance(value, bytes) else None

    def cell_label(self, row, column):
        """'<database> > table.column, row N' -- where the bytes are."""
        header = self.grid.horizontalHeaderItem(column)
        name = self._source.get('name') or 'database'
        return (f"{name} > {getattr(self, '_table', '?')}."
                f"{header.text() if header else column}, row {row + 1}")

    def _open_cell(self, row, column):
        content = self.cell_bytes(row, column)
        if content is not None and self.blob_opener is not None:
            self.blob_opener(content, self.cell_label(row, column))

    def _cell_menu(self, point):
        index = self.grid.indexAt(point)
        if not index.isValid():
            return
        row, column = index.row(), index.column()
        content = self.cell_bytes(row, column)
        if content is None:
            return
        from trace_app.ui.widgets.context_menus import show_menu
        menu = QMenu(self)
        what = f"{blob_kind(content)}, {len(content):,} bytes"
        if self.blob_opener is not None:
            action = menu.addAction(f"Open in Viewer ({what})")
            action.triggered.connect(lambda: self._open_cell(row, column))
        menu.addAction("Export Bytes…").triggered.connect(
            lambda: self.export_cell(row, column))
        menu.addAction("Copy as Hex").triggered.connect(
            lambda: QApplication.clipboard().setText(content.hex(' ')))
        show_menu(menu, self.grid.viewport().mapToGlobal(point))

    def export_cell(self, row, column, path=None):
        """Save a cell's bytes -- hashed, read back, audited."""
        from trace_app.core import evidence_export
        from trace_app.ui.dialogs import message
        content = self.cell_bytes(row, column)
        if content is None:
            return None
        label = self.cell_label(row, column)
        if path is None:
            from trace_app.core.settings import export_dir
            suggested = os.path.join(export_dir(), _safe(label) + '.bin')
            path, _ = QFileDialog.getSaveFileName(self, "Export Bytes",
                                                  suggested)
            if not path:
                return None
        try:
            digests = evidence_export.save_bytes(path, content,
                                                 'database cell exported',
                                                 label)
        except Exception as exc:
            message.warning(self, "Export failed", str(exc))
            return None
        message.information(self, "Exported",
                            f"{len(content):,} bytes written to\n{path}\n\n"
                            f"SHA-256 {digests['sha256']}\nWritten copy: "
                            f"{digests['written_copy_check']}")
        return path
