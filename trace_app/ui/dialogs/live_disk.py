"""Choose a physical disk to read live (core/live_disk.py).

Lists the machine's disks -- size, model, bus, removable, and which one the
running system is on -- read without privileges. Choosing one starts the
read-only helper behind the platform's administrator prompt when it is
opened. The dialog says plainly what a live read is not: a forensic image.
"""

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QDialogButtonBox,
                               QHeaderView, QLabel, QTableWidget,
                               QTableWidgetItem, QVBoxLayout)

from trace_app.core import live_disk
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui import icons
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.LiveDiskDialog')


class LiveDiskDialog(QDialog):
    """`device` is the chosen disk's path once accepted."""

    COLUMNS = ['Disk', 'Model', 'Size', 'Bus', 'Notes']

    def __init__(self, parent=None, disks=None):
        super().__init__(parent)
        self.setWindowTitle("Read a Live Disk")
        self.setObjectName("liveDiskDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.device = None
        self.disks = list_disks() if disks is None else list(disks)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 12)
        layout.setSpacing(10)
        intro = QLabel(
            "Read a disk attached to this computer, read-only, without "
            "imaging it first. Opening it asks for administrator rights.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        warning = QLabel(
            "A live read is a preview, not evidence: a disk that is mounted "
            "and in use changes while it is read, and TRACE does not stop "
            "the operating system writing to it. For evidence, connect the "
            "disk through a hardware write blocker and image it.")
        warning.setObjectName("wizardFieldNote")
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self.table = QTableWidget(len(self.disks), len(self.COLUMNS))
        self.table.setObjectName("triageTable")
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        for row, disk in enumerate(self.disks):
            notes = []
            if disk.get('system'):
                notes.append("the running system's disk")
            if disk.get('removable'):
                notes.append('removable')
            cells = [disk.get('name') or disk['path'],
                     disk.get('model') or '',
                     FileSystemUtils.get_readable_size(disk['size'])
                     if disk.get('size') else '—',
                     disk.get('detail') or '', ', '.join(notes)]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setToolTip(disk['path'])
                if column == 0:
                    item.setData(Qt.UserRole, disk['path'])
                self.table.setItem(row, column, item)
        for column, width in enumerate((110, 280, 90, 70)):
            self.table.setColumnWidth(column, width)
        self.table.itemSelectionChanged.connect(self._update)
        self.table.itemDoubleClicked.connect(lambda _item: self._accept())
        layout.addWidget(self.table, 1)
        if not self.disks:
            empty = QLabel("No disks could be listed on this computer.")
            empty.setObjectName("wizardFieldNote")
            layout.addWidget(empty)

        self.note = QLabel()
        self.note.setObjectName("wizardFieldNote")
        self.note.setWordWrap(True)
        layout.addWidget(self.note)

        buttons = QDialogButtonBox()
        self.read_button = buttons.addButton("Read This Disk",
                                             QDialogButtonBox.AcceptRole)
        buttons.addButton(QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.resize(720, 360)
        self._update()

    def _selected(self):
        rows = self.table.selectionModel().selectedRows()
        return self.disks[rows[0].row()] if rows else None

    def _update(self):
        disk = self._selected()
        self.read_button.setEnabled(disk is not None)
        if disk is None:
            self.note.setText('')
        elif disk.get('system'):
            self.note.setText(
                "This is the disk the running system is on: it is being "
                "written to as you read it, and what TRACE sees is "
                "inconsistent by nature. Read it only to look.")
        else:
            self.note.setText(disk['path'])

    def _accept(self):
        disk = self._selected()
        if disk is not None:
            self.device = disk['path']
            self.accept()


def list_disks():
    return live_disk.list_disks()


def choose_live_disk(parent=None):
    """Run the dialog: the chosen disk's path, or None."""
    dialog = LiveDiskDialog(parent)
    if dialog.exec() == QDialog.Accepted:
        return dialog.device
    return None
