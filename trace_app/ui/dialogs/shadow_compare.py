"""Compare Shadow Copies: what changed between a Volume Shadow Copy and a
later one, or the live volume (core/vss_compare.py).

The comparison runs in a child process (job 'vss_compare'), so a large
volume does not hold the window. Nothing is stored: the differences are
listed here, filtered by kind and path, and a double-click opens the
version that matters -- a deleted file from the snapshot that still has
it, anything else as it is in the later state.
"""

import logging
from datetime import datetime, timezone

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QDialog, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMenu, QPushButton, QTableWidget,
                               QTableWidgetItem, QVBoxLayout)

from trace_app.core import vss_compare
from trace_app.core.case import make_artifact_ref
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui import icons
from trace_app.ui.process_worker import ProcessWorker

logger = logging.getLogger('TRACE.ShadowCompare')

LIVE = 'live'
COLUMNS = ('Change', 'Path', 'Size before', 'Modified before (UTC)',
           'Size after', 'Modified after (UTC)', 'Was at')
CHANGE_LABELS = {vss_compare.DELETED: 'Deleted', vss_compare.ADDED: 'Added',
                 vss_compare.CHANGED: 'Changed',
                 vss_compare.RENAMED: 'Renamed or moved'}


class ShadowCompareWorker(ProcessWorker):
    """Runs the comparison in a child process; the rows arrive at the end."""

    progressed = Signal(object, object, str)
    compared = Signal(list, str)

    kind = 'vss_compare'

    def __init__(self, params, parent=None):
        super().__init__(params, parent)
        self.rows = []

    def on_progress(self, done, total, text):
        self.progressed.emit(done, total, text)

    def on_item(self, record):
        self.rows.append(record)

    def on_done(self, count, error):
        self.compared.emit(self.rows, error)


def _when(seconds):
    if not seconds:
        return ''
    try:
        return datetime.fromtimestamp(seconds, timezone.utc).strftime(
            '%Y-%m-%d %H:%M:%S')
    except (OverflowError, OSError, ValueError):
        return ''


class ShadowCompareDialog(QDialog):
    """`shadows`: [{'key', 'index', 'created'}] of the volume at sector
    `volume`, oldest first. `before`: the snapshot key to start from."""

    #: (image path, artifact ref, file name): open that version.
    file_requested = Signal(str, str, str)

    def __init__(self, image_path, volume, label, shadows, unlock=None,
                 before=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Compare Shadow Copies — {label}")
        self.setObjectName("shadowCompareDialog")
        self.setWindowIcon(icons.icon(icons.SHADOW_COPY))
        self.resize(1100, 640)
        self.image_path, self.volume, self.label = image_path, volume, label
        self.shadows = list(shadows)
        self.unlock = unlock
        self.rows = []
        self.worker = None

        layout = QVBoxLayout(self)
        intro = QLabel(
            "What changed between a snapshot and a later state of the "
            "volume: files deleted, added, changed or renamed. Read from "
            "the file system's own records; nothing is written.")
        intro.setWordWrap(True)
        intro.setObjectName("dialogIntro")
        layout.addWidget(intro)

        choose = QHBoxLayout()
        choose.addWidget(QLabel("From"))
        self.before_combo = QComboBox()
        for shadow in self.shadows:
            self.before_combo.addItem(self._shadow_text(shadow),
                                      shadow['key'])
        choose.addWidget(self.before_combo, 1)
        choose.addWidget(QLabel("to"))
        self.after_combo = QComboBox()
        choose.addWidget(self.after_combo, 1)
        self.system_box = QCheckBox("Include NTFS metadata files")
        self.system_box.setToolTip("$MFT, $LogFile and the rest change with "
                                   "every write; left out by default.")
        choose.addWidget(self.system_box)
        self.compare_button = QPushButton("Compare")
        self.compare_button.setObjectName("primaryButton")
        self.compare_button.clicked.connect(self.start)
        choose.addWidget(self.compare_button)
        layout.addLayout(choose)

        self.status = QLabel("Choose two states and compare.")
        self.status.setObjectName("dialogStatus")
        layout.addWidget(self.status)

        filters = QHBoxLayout()
        self.kind_combo = QComboBox()
        self.kind_combo.addItem("Every change", None)
        for change in vss_compare.CHANGES:
            self.kind_combo.addItem(CHANGE_LABELS[change], change)
        self.kind_combo.currentIndexChanged.connect(self._fill)
        filters.addWidget(self.kind_combo)
        self.filter_box = QLineEdit()
        self.filter_box.setPlaceholderText("Filter by path")
        self.filter_box.setClearButtonEnabled(True)
        self.filter_box.textChanged.connect(self._fill)
        filters.addWidget(self.filter_box, 1)
        layout.addLayout(filters)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setObjectName("shadowCompareTable")
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.table.cellDoubleClicked.connect(self._open_row)
        layout.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        layout.addLayout(buttons)

        self.before_combo.currentIndexChanged.connect(self._later_states)
        if before is not None:
            index = self.before_combo.findData(before)
            if index >= 0:
                self.before_combo.setCurrentIndex(index)
        elif self.shadows:
            self.before_combo.setCurrentIndex(len(self.shadows) - 1)
        self._later_states()

    # --- choosing ------------------------------------------------------------

    @staticmethod
    def _shadow_text(shadow):
        created = shadow['created'].strftime('%Y-%m-%d %H:%M:%S UTC') \
            if shadow.get('created') else 'time unknown'
        return f"Shadow copy {shadow['index'] + 1} ({created})"

    @Slot()
    def _later_states(self):
        """The later states the chosen snapshot can be compared with: the
        snapshots after it, and the live volume (the default)."""
        chosen = self.before_combo.currentIndex()
        self.after_combo.clear()
        for shadow in self.shadows[chosen + 1:]:
            self.after_combo.addItem(self._shadow_text(shadow),
                                     shadow['key'])
        self.after_combo.addItem("Live volume (as the image holds it now)",
                                 LIVE)
        self.after_combo.setCurrentIndex(self.after_combo.count() - 1)

    def _after_key(self):
        data = self.after_combo.currentData()
        return self.volume if data == LIVE else data

    # --- running -------------------------------------------------------------

    @Slot()
    def start(self):
        if self.worker is not None or self.before_combo.currentData() is None:
            return
        self.rows = []
        self._fill()
        self.compare_button.setEnabled(False)
        self.status.setText("Reading both states of the volume…")
        self._compared = (self.before_combo.currentData(), self._after_key())
        self.worker = ShadowCompareWorker({
            'image_path': self.image_path, 'unlock': self.unlock,
            'volume': self.volume, 'before': self._compared[0],
            'after': self._compared[1],
            'system': self.system_box.isChecked()}, self)
        self.worker.progressed.connect(self._progressed)
        self.worker.compared.connect(self._finished)
        self.worker.finished.connect(self._worker_ended)
        self.worker.start()

    @Slot(int, int, str)
    def _progressed(self, done, total, text):
        self.status.setText(text + '…' if done < total else text)

    @Slot(list, str)
    def _finished(self, rows, error):
        self.compare_button.setEnabled(True)
        if error:
            self.status.setText(f"Could not compare: {error}")
            return
        self.rows = rows
        counts = vss_compare.summary(rows)
        self.status.setText(
            f"{self.before_combo.currentText()} → "
            f"{self.after_combo.currentText()}: " + ', '.join(
                f"{counts[c]:,} {CHANGE_LABELS[c].lower()}"
                for c in vss_compare.CHANGES))
        self._fill()

    @Slot()
    def _worker_ended(self):
        worker, self.worker = self.worker, None
        if worker is not None:
            worker.wait()
            worker.deleteLater()

    def closeEvent(self, event):
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(10000)
        super().closeEvent(event)

    # --- showing -------------------------------------------------------------

    def shown_rows(self):
        kind = self.kind_combo.currentData()
        text = self.filter_box.text().strip().lower()
        return [row for row in self.rows
                if (kind is None or row['change'] == kind)
                and (not text or text in row['path'].lower())]

    @Slot()
    def _fill(self, *_args):
        rows = self.shown_rows()
        table = self.table
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for number, row in enumerate(rows):
            before, after = row['before'] or {}, row['after'] or {}
            was = before.get('path', '') \
                if row['change'] == vss_compare.RENAMED else ''
            cells = (CHANGE_LABELS[row['change']], row['path'],
                     self._size(before), _when(before.get('modified')),
                     self._size(after), _when(after.get('modified')), was)
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column == 0:
                    item.setData(Qt.UserRole, row)
                table.setItem(number, column, item)
        table.setSortingEnabled(True)
        table.resizeColumnToContents(0)

    @staticmethod
    def _size(entry):
        if not entry or entry.get('is_dir'):
            return 'folder' if entry else ''
        return FileSystemUtils.get_readable_size(entry.get('size', 0))

    # --- opening -------------------------------------------------------------

    def _row(self, number):
        item = self.table.item(number, 0)
        return item.data(Qt.UserRole) if item is not None else None

    def _open(self, row, which):
        """Open the earlier ('before') or later ('after') version."""
        entry = row.get(which)
        if not entry or entry.get('is_dir'):
            return
        key = self._compared[0] if which == 'before' else self._compared[1]
        ref = make_artifact_ref(key, entry['inode'], entry.get('sequence'))
        self.file_requested.emit(self.image_path, ref,
                                 entry['path'].rsplit('/', 1)[-1])

    @Slot(int, int)
    def _open_row(self, number, _column):
        row = self._row(number)
        if row is not None:
            self._open(row, 'before' if row['change'] ==
                       vss_compare.DELETED else 'after')

    @Slot(object)
    def _menu(self, position):
        from trace_app.ui.widgets.context_menus import show_menu
        row = self._row(self.table.rowAt(position.y()))
        if row is None:
            return
        menu = QMenu(self)
        if row['before'] and not row['before'].get('is_dir'):
            menu.addAction("Open the Earlier Version").triggered.connect(
                lambda _=False, r=row: self._open(r, 'before'))
        if row['after'] and not row['after'].get('is_dir'):
            menu.addAction("Open the Later Version").triggered.connect(
                lambda _=False, r=row: self._open(r, 'after'))
        show_menu(menu, self.table.viewport().mapToGlobal(position))
