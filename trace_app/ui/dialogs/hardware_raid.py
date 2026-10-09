"""Rebuild a hardware RAID from parameters (core/hwraid.py): the Assemble
dialog's second tab.

The examiner ticks the member images among the open evidence, puts them
in order (a placeholder where a disk is missing), and sets the level,
stripe size, parity layout and delay -- or asks TRACE to detect them: it
tries combinations and ranks them by how many files they read parse as
their format, best first; choosing one fills the fields in.
"""

import logging
import os

from PySide6.QtCore import Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFormLayout,
                               QHBoxLayout, QHeaderView, QLabel,
                               QListWidget, QListWidgetItem, QPushButton,
                               QSpinBox, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from trace_app.core import assembly, hwraid
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.HardwareRaid')

MISSING = "(missing disk)"
LEVEL_NAMES = (('5', 'RAID 5'), ('0', 'RAID 0'), ('6', 'RAID 6'),
               ('1', 'RAID 1'), ('jbod', 'JBOD (spanned)'))


class _Detect(QThread):
    """Runs hwraid.detect. Signals only: the panel's bound slots receive
    them on the GUI thread."""
    progress = Signal(int, int)
    done = Signal(list)

    def __init__(self, members, names, parent=None):
        super().__init__(parent)
        self.members, self.names = members, names
        self.stopped = False

    def run(self):
        try:
            ranked = hwraid.detect(self.members, self.names,
                                   should_stop=lambda: self.stopped,
                                   progress=self.progress.emit)
        except Exception as exc:
            logger.warning("RAID detection failed: %s", exc)
            ranked = []
        self.done.emit(ranked)


class HardwareRaidPanel(QWidget):
    """`handlers` {path: ImageHandler} of the open evidence; `names`
    {path: display name}."""

    def __init__(self, handlers, names=None, parent=None):
        super().__init__(parent)
        self.handlers = {p: h for p, h in (handlers or {}).items()
                         if h is not None and getattr(h, 'logical_fs', None)
                         is None and not assembly.is_assembly(p)}
        self.names = names or {}
        self._worker = None
        self._ranked = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 0)
        intro = QLabel(
            "Disks of a controller RAID (HP Smart Array, Adaptec, a "
            "motherboard RAID) carry no description of the array: tick "
            "them, put them in order and give the parameters -- or let "
            "TRACE detect them from what the files it reads look like.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        body = QHBoxLayout()
        layout.addLayout(body, 1)
        left = QVBoxLayout()
        body.addLayout(left, 3)
        self.members = QListWidget()
        self.members.setObjectName("raidMembers")
        self.members.setDragDropMode(QAbstractItemView.InternalMove)
        for path in sorted(self.handlers, key=_natural):
            item = QListWidgetItem(self.names.get(path) or
                                   os.path.basename(path))
            item.setData(Qt.UserRole, path)
            item.setToolTip(path)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            self.members.addItem(item)
        left.addWidget(QLabel("Member disks, in order:"))
        left.addWidget(self.members, 1)
        buttons = QHBoxLayout()
        for text, slot in (("Up", self._up), ("Down", self._down),
                           ("Add missing disk", self._add_missing),
                           ("Remove", self._remove)):
            button = QPushButton(text)
            button.clicked.connect(slot)
            buttons.addWidget(button)
        left.addLayout(buttons)

        form = QFormLayout()
        body.addLayout(form, 2)
        self.level = QComboBox()
        for value, text in LEVEL_NAMES:
            self.level.addItem(text, value)
        self.stripe = QComboBox()
        for size in hwraid.CHUNKS:
            self.stripe.addItem(f"{size // 1024} KiB", size)
        self.stripe.setCurrentIndex(hwraid.CHUNKS.index(65536))
        self.layout_box = QComboBox()
        for name in hwraid.LAYOUTS:
            self.layout_box.addItem(name, name)
        self.delay = QSpinBox()
        self.delay.setRange(1, 1024)
        self.delay.setToolTip("Rows before parity moves to the next disk: "
                              "1 for most controllers; HP / Compaq Smart "
                              "Array often 4 or 16")
        self.offset = QSpinBox()
        self.offset.setRange(0, 2 ** 31 - 1)
        self.offset.setSuffix(" sectors")
        self.offset.setToolTip("Where each disk's data starts (a "
                               "controller's own metadata before it)")
        form.addRow("Level", self.level)
        form.addRow("Stripe size", self.stripe)
        form.addRow("Parity layout", self.layout_box)
        form.addRow("Parity delay", self.delay)
        form.addRow("Data offset", self.offset)
        self.detect_button = QPushButton("Detect parameters")
        self.detect_button.setToolTip(
            "Try orders, stripe sizes and layouts; rank them by the files "
            "they read (seconds to a minute)")
        self.detect_button.clicked.connect(self.detect)
        form.addRow(self.detect_button)

        self.results = QTableWidget(0, 3)
        self.results.setObjectName("triageTable")
        self.results.setHorizontalHeaderLabels(
            ['Files valid', 'Parameters', 'Order'])
        self.results.verticalHeader().setVisible(False)
        self.results.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.results.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results.setSelectionMode(QAbstractItemView.SingleSelection)
        self.results.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results.setItemDelegate(NoFocusDelegate(self.results))
        self.results.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch)
        self.results.itemSelectionChanged.connect(self._apply_selected)
        layout.addWidget(self.results, 1)
        self.status = QLabel()
        self.status.setObjectName("wizardFieldNote")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.level.currentIndexChanged.connect(self._level_changed)
        self._level_changed()
        if not self.handlers:
            self.status.setText("Open the member disks' images first.")

    # --- the member list ------------------------------------------------

    def _move(self, step):
        row = self.members.currentRow()
        target = row + step
        if row < 0 or not 0 <= target < self.members.count():
            return
        item = self.members.takeItem(row)
        self.members.insertItem(target, item)
        self.members.setCurrentRow(target)

    def _up(self):
        self._move(-1)

    def _down(self):
        self._move(1)

    def _add_missing(self):
        item = QListWidgetItem(MISSING)
        item.setData(Qt.UserRole, None)
        item.setToolTip("A disk not imaged: rebuilt from parity (RAID 5 "
                        "and 6, one disk)")
        row = self.members.currentRow()
        self.members.insertItem(row + 1 if row >= 0 else
                                self.members.count(), item)

    def _remove(self):
        row = self.members.currentRow()
        if row >= 0 and self.members.item(row).data(Qt.UserRole) is None:
            self.members.takeItem(row)

    def selection(self):
        """(member paths, order) from the list: ticked images and missing
        placeholders, in list order; order indexes the paths."""
        paths, order = [], []
        for row in range(self.members.count()):
            item = self.members.item(row)
            path = item.data(Qt.UserRole)
            if path is None:
                order.append(None)
            elif item.checkState() == Qt.Checked:
                order.append(len(paths))
                paths.append(path)
        return paths, order

    def _level_changed(self):
        parity = self.level.currentData() in ('5', '6')
        self.layout_box.setEnabled(parity)
        self.delay.setEnabled(parity)
        self.stripe.setEnabled(self.level.currentData() != 'jbod')

    # --- parameters --------------------------------------------------------

    def params(self):
        _paths, order = self.selection()
        return hwraid.Params(self.level.currentData(),
                             self.stripe.currentData(),
                             self.layout_box.currentData(),
                             self.offset.value() * 512, order,
                             self.delay.value())

    def group(self):
        """The group to save, or raises hwraid.RaidError saying why not."""
        paths, order = self.selection()
        if len(paths) < 2:
            raise hwraid.RaidError("Tick at least two member disks")
        params = self.params()
        hwraid.build([(self.handlers[p].read, self.handlers[p].get_size())
                      for p in paths], params)
        name = os.path.basename(os.path.dirname(paths[0])) or 'Hardware RAID'
        return assembly.hardware_group(paths, params, name)

    # --- detection --------------------------------------------------------

    @Slot()
    def detect(self):
        paths, _order = self.selection()
        if len(paths) < 2:
            self.status.setText("Tick at least two member disks to detect "
                                "their RAID.")
            return
        self._detected_paths = paths
        members = [(self.handlers[p].read, self.handlers[p].get_size())
                   for p in paths]
        self.results.setRowCount(0)
        self.detect_button.setEnabled(False)
        self.status.setText("Detecting…")
        worker = _Detect(members, [os.path.basename(p) for p in paths], self)
        worker.progress.connect(self._progress)
        worker.done.connect(self._detected)
        worker.finished.connect(worker.deleteLater)
        self._worker = worker
        worker.start()

    @Slot(int, int)
    def _progress(self, done, total):
        self.status.setText(f"Detecting… {done:,} of {total:,} "
                            f"combinations tried")

    @Slot(list)
    def _detected(self, ranked):
        self._worker = None
        self.detect_button.setEnabled(True)
        self._ranked = ranked
        if not ranked:
            self.status.setText("No combination opened a file system. Check "
                                "the disks ticked, or try a data offset.")
            return
        self.results.setRowCount(len(ranked))
        for row, (_score, params, evidence) in enumerate(ranked):
            valid = (f"{evidence['valid']} of {evidence['checked']}"
                     if evidence['checked'] else
                     f"{evidence['files']} files")
            order = ', '.join(
                MISSING if index is None else
                os.path.basename(self._detected_paths[index])
                for index in params.order)
            for column, text in enumerate((valid, params.describe(), order)):
                self.results.setItem(row, column, QTableWidgetItem(text))
        best = ranked[0][2]
        self.status.setText(
            f"Best: {ranked[0][1].describe()} -- {best['valid']} of "
            f"{best['checked']} files checked parse as their format. "
            f"Selected below; Assemble to open it.")
        self.results.selectRow(0)

    def _apply_selected(self):
        rows = self.results.selectionModel().selectedRows()
        if not rows or rows[0].row() >= len(self._ranked):
            return
        params = self._ranked[rows[0].row()][1]
        self.level.setCurrentIndex(self.level.findData(params.level))
        self.stripe.setCurrentIndex(max(0, self.stripe.findData(
            params.chunk)))
        self.layout_box.setCurrentIndex(self.layout_box.findData(
            params.layout))
        self.delay.setValue(params.delay)
        self.offset.setValue(params.offset // 512)
        # The list follows the candidate's order: its disks ticked, in
        # order, with placeholders for missing ones; others below.
        paths = self._detected_paths
        others = [self.members.item(r) for r in range(self.members.count())
                  if self.members.item(r).data(Qt.UserRole) not in paths
                  and self.members.item(r).data(Qt.UserRole) is not None]
        others = [(i.text(), i.data(Qt.UserRole)) for i in others]
        self.members.clear()
        for index in params.order:
            if index is None:
                item = QListWidgetItem(MISSING)
                item.setData(Qt.UserRole, None)
            else:
                path = paths[index]
                item = QListWidgetItem(self.names.get(path) or
                                       os.path.basename(path))
                item.setData(Qt.UserRole, path)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked)
            self.members.addItem(item)
        for text, path in others:
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, path)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            self.members.addItem(item)

    def stop(self):
        if self._worker is not None:
            self._worker.stopped = True
            self._worker.wait(5000)


def _natural(path):
    import re
    name = os.path.basename(path).lower()
    return [int(t) if t.isdigit() else t for t in re.split(r'(\d+)', name)]
