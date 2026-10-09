"""Deleted files: everything the file systems still remember deleting, and
how much of each is left (core/deleted.py).

A Triage sub-tab. Each row is a deleted file or folder with its original
path and times, and its state: recoverable, partly overwritten,
overwritten, resident in its MFT entry, its entry reused by another file,
or with no record of where its data was. A row previews the file's content
as the file system still describes it; double-click goes to it in the
listing.
"""

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QHBoxLayout, QHeaderView, QLabel, QSizePolicy,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from trace_app.core import deleted
from trace_app.infra.constants import CONTROL_HEIGHT, TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.row_preview import connect_row_preview

logger = logging.getLogger('TRACE.DeletedPanel')

SHOWN_LIMIT = 50000
_COLUMNS = ('Name', 'Evidence', 'State', 'Size', 'Overwritten', 'Pieces',
            'Modified', 'Entry changed', 'Path')
_TONE = {deleted.RECOVERABLE: 'clean', deleted.RESIDENT: 'clean',
         deleted.PARTLY: 'suspicious', deleted.OVERWRITTEN: 'malicious',
         deleted.REUSED: 'unknown', deleted.NO_DATA: 'unknown',
         deleted.START_ONLY: 'suspicious',
         deleted.POSSIBLY: 'suspicious'}
_MEANING = {
    deleted.RECOVERABLE: "The entry is unused and none of its clusters is "
                         "held by a live file: its content is as it was.",
    deleted.RESIDENT: "The data is inside the MFT entry itself, which is "
                      "not reused.",
    deleted.PARTLY: "Some of its clusters now belong to live files.",
    deleted.OVERWRITTEN: "All of its clusters now belong to live files.",
    deleted.REUSED: "Its metadata now describes another file: only the "
                    "name is left.",
    deleted.NO_DATA: "Its entry no longer records where its data was (ext3 "
                     "and ext4 clear it on deletion); carving may still "
                     "find it.",
    deleted.POSSIBLY: "A deleted file written later may lie over its "
                      "clusters: if it was written after this one was "
                      "deleted, this one's data is gone. FAT keeps no "
                      "deletion time to say which.",
    deleted.START_ONLY: "FAT kept where it began, not where the rest of it "
                        "lay, and another deleted file's data follows its "
                        "start: it was in pieces. Only its first cluster is "
                        "known to be its own; what reads after it may be "
                        "another file's.",
}


class DeletedWorker(ProcessWorker):
    progressed = Signal(int, int, str)
    finished_deleted = Signal(int, str)

    kind = 'deleted'

    def __init__(self, image_path, case_folder, evidence_id, parent=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id}, parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_deleted.emit(count, error)


class _Number(QTableWidgetItem):
    def __lt__(self, other):
        return (self.data(Qt.UserRole + 1) or 0) < \
            (other.data(Qt.UserRole + 1) or 0)


class DeletedFilesPanel(QWidget):
    file_selected = Signal(dict)
    file_activated = Signal(dict)
    file_menu_requested = Signal(dict, object)
    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("deletedPanel")
        self.case = None
        self.evidence_id = None
        self._names = {}
        self.count = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)
        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.state_combo = QComboBox()
        self.state_combo.setObjectName("deletedStateCombo")
        self.state_combo.setFixedHeight(CONTROL_HEIGHT)
        self.state_combo.addItem("Every state", None)
        for state in deleted.STATES:
            self.state_combo.addItem(state.capitalize(), state)
        self.state_combo.currentIndexChanged.connect(
            lambda _index: self.refresh())
        bar.addWidget(self.state_combo)
        self.files_box = QCheckBox("Files only")
        self.files_box.setChecked(True)
        self.files_box.toggled.connect(lambda _on: self.refresh())
        bar.addWidget(self.files_box)
        self.status_label = QLabel()
        self.status_label.setObjectName("indicatorStatus")
        self.status_label.setSizePolicy(QSizePolicy.Ignored,
                                        QSizePolicy.Preferred)
        bar.addWidget(self.status_label, 1)
        layout.addLayout(bar)

        self.table = QTableWidget()
        self.table.setObjectName("triageTable")
        self.table.setColumnCount(len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSortingEnabled(True)
        connect_row_preview(self.table, self.file_selected.emit)
        self.table.itemDoubleClicked.connect(
            lambda item: self.file_activated.emit(
                self.table.item(item.row(), 0).data(Qt.UserRole)))
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.table, 1)
        self.refresh()

    def set_case(self, case):
        self.case = case
        self._names = {r['id']: r.get('display_name')
                       or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                       for r in case.evidence()} if case else {}
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        if evidence_id == self.evidence_id:
            return
        self.evidence_id = evidence_id
        self.refresh()

    def shutdown(self):
        pass

    def refresh(self):
        rows = []
        if self.case is not None:
            rows = self.case.deleted_files(self.evidence_id,
                                           self.state_combo.currentData(),
                                           limit=SHOWN_LIMIT)
            if self.files_box.isChecked():
                rows = [r for r in rows if not r['is_dir']]
        # A $R file is a deleted file's content, renamed by the Recycle
        # Bin; its $I record says what it was. Shown with its name.
        origins = self.case.recycle_origins(self.evidence_id) \
            if self.case is not None and any(
                (r.get('name') or '')[:2].upper() in ('$R', '$I')
                for r in rows) else {}
        table = self.table
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            size = int(row.get('size') or 0)
            lost = int(row.get('overwritten') or 0)
            # FAT's times are local wall-clock digits: never shown as UTC.
            zone = " (local, no zone)" if (row.get('detail') or {}).get(
                'times_local') else ' UTC'
            cells = [
                QTableWidgetItem(row.get('name') or ''),
                QTableWidgetItem(self._names.get(row['evidence_id'], '')),
                QTableWidgetItem((row.get('state') or '').capitalize()),
                _Number(FileSystemUtils.get_readable_size(size)
                        if size else ''),
                _Number(FileSystemUtils.get_readable_size(lost)
                        if lost else ''),
                _Number(str(row.get('runs') or '')),
                QTableWidgetItem(row['modified_utc'] + zone
                                 if row.get('modified_utc') else ''),
                QTableWidgetItem(row['changed_utc'] + zone
                                 if row.get('changed_utc') else ''),
                QTableWidgetItem(row.get('path') or '')]
            cells[3].setData(Qt.UserRole + 1, size)
            cells[4].setData(Qt.UserRole + 1, lost)
            cells[5].setData(Qt.UserRole + 1, row.get('runs') or 0)
            tone = _TONE.get(row.get('state'))
            if tone:
                cells[2].setForeground(verdict_brush(tone))
            cells[2].setToolTip(_MEANING.get(row.get('state'), ''))
            cells[7].setToolTip("When the entry last changed -- on NTFS and "
                                "ext, usually its deletion")
            cells[8].setToolTip(row.get('path') or '')
            origin = origins.get((row['evidence_id'],
                                  (row.get('artifact_ref') or '')
                                  .split(':', 1)[0] + ':',
                                  (row.get('path') or '').lower()))
            if origin:
                cells[0].setText(f"{row.get('name') or ''} — was "
                                 f"{origin['original']}")
                cells[0].setToolTip(
                    f"The Recycle Bin's {origin['part']} for "
                    f"{origin['original']}, deleted "
                    f"{origin['deleted'] or 'at a time not recorded'}"
                    + (f" by {origin['user']}" if origin['user'] else '')
                    + (f"; {origin['record']}" if origin['record'] else ''))
            cells[0].setData(Qt.UserRole, dict(
                row, artifact_name=row.get('name'),
                artifact_path=row.get('path'), recycle_origin=origin))
            for column, cell in enumerate(cells):
                table.setItem(position, column, cell)
        table.setSortingEnabled(True)
        for column, width in enumerate((200, 140, 130, 80, 90, 60, 150,
                                        150)):
            table.setColumnWidth(column, width)
        self.count = len(rows)
        if self.case is None:
            text = "Deleted files are listed into a case."
        else:
            counts = self.case.deleted_counts(self.evidence_id)
            if not counts:
                text = ("Nothing listed yet. Run Analysis ▸ Deleted files "
                        "lists everything the file systems still remember "
                        "deleting.")
            else:
                text = ', '.join(f"{counts[s]:,} {s}" for s in deleted.STATES
                                 if counts.get(s))
                if len(rows) >= SHOWN_LIMIT:
                    text += f" — the first {SHOWN_LIMIT:,} shown"
        self.status_label.setText(text)
        self.status_label.setToolTip(text)
        self.count_changed.emit(self.count)

    def select(self, evidence_id, artifact_ref):
        """Select the row for one deleted file (from a Recycle Bin record),
        widening the filters if they hide it. True when it is listed."""
        def find():
            for position in range(self.table.rowCount()):
                row = self.table.item(position, 0).data(Qt.UserRole) or {}
                if row.get('evidence_id') == evidence_id and \
                        row.get('artifact_ref') == artifact_ref:
                    return position
            return None
        position = find()
        if position is None and self.state_combo.currentIndex() != 0:
            self.state_combo.setCurrentIndex(0)
            position = find()
        if position is None:
            return False
        self.table.selectRow(position)
        self.table.scrollToItem(self.table.item(position, 0))
        return True

    def _menu(self, point):
        item = self.table.itemAt(point)
        if item is None:
            return
        row = self.table.item(item.row(), 0).data(Qt.UserRole)
        self.file_menu_requested.emit(
            row, self.table.viewport().mapToGlobal(point))
