"""Assemble a RAID array or multi-disk Btrfs file system (core/assembly.py).

Two tabs. *Found on the disks*: the multi-disk volumes that describe
themselves (Linux md, Btrfs), with how many members were found and whether
that is enough to read them. *Hardware RAID*: disks of a controller RAID,
which describe nothing, rebuilt from parameters given or detected
(ui/dialogs/hardware_raid.py). Either way a descriptor is saved that opens
as evidence of its own; the members stay evidence too.
"""

from PySide6.QtWidgets import (QAbstractItemView, QDialog, QDialogButtonBox,
                               QHeaderView, QLabel, QTableWidget,
                               QTableWidgetItem, QTabWidget, QVBoxLayout,
                               QWidget)

from trace_app.core import assembly
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui import icons
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

#: Members an array can lose and still be read by core/mdraid.py, by
#: RAID level (RAID6 too: one, rebuilt from P -- Q is not used).
_SPARE = {0: 0, 1: None, 4: 1, 5: 1, 6: 1, 10: 1}


def readable(group):
    """(True/False, why) for whether the members found are enough."""
    found = len({m['slot'] for m in group['members']})
    missing = group['needed'] - found
    if missing <= 0:
        return True, 'every member found'
    if group['kind'] == assembly.BTRFS:
        return True, (f"{missing} device{'s' if missing != 1 else ''} "
                      f"missing: what is mirrored or covered by parity is "
                      f"read; anything only on the missing device is not")
    spare = _SPARE.get(group['level'], 0)
    if spare is None or missing <= spare:
        return True, (f"{missing} missing; rebuilt from the others"
                      if group['level'] != 1 else f"{missing} missing; "
                      f"a mirror needs only one")
    return False, (f"{missing} missing: RAID{group['level']} cannot be read "
                   f"without {'them' if missing != 1 else 'it'}")


class AssembleDialog(QDialog):
    """`group` is the chosen volume once accepted."""

    COLUMNS = ['Volume', 'Members', 'Found', 'Readable']

    def __init__(self, groups, names=None, parent=None, handlers=None):
        super().__init__(parent)
        self.setWindowTitle("Assemble RAID or Multi-Disk Volume")
        self.setObjectName("assembleDialog")
        self.setWindowIcon(icons.icon(icons.LOGO))
        self.group = None
        self.groups = list(groups)
        names = names or {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 12)
        outer.setSpacing(10)
        self.tabs = QTabWidget()
        outer.addWidget(self.tabs, 1)
        found = QWidget()
        layout = QVBoxLayout(found)
        layout.setContentsMargins(0, 8, 0, 0)
        self.tabs.addTab(found, "Found on the disks")
        from trace_app.ui.dialogs.hardware_raid import HardwareRaidPanel
        self.hardware = HardwareRaidPanel(handlers or {}, names, self)
        self.tabs.addTab(self.hardware, "Hardware RAID")
        if not self.groups and self.hardware.handlers:
            self.tabs.setCurrentWidget(self.hardware)
        intro = QLabel(
            "Disks imaged one by one that belonged to one Linux RAID array "
            "or one Btrfs file system. Assembling one adds it as evidence "
            "read across its members; each member stays evidence of its "
            "own, and nothing is written to them.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.table = QTableWidget(len(self.groups), len(self.COLUMNS))
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
        for row, group in enumerate(self.groups):
            ok, why = readable(group)
            what = (f"RAID{group['level']}" if group['kind'] ==
                    assembly.MDRAID else 'Btrfs')
            members = ', '.join(
                names.get(m['image']) or m['image'].replace('\\', '/')
                .rsplit('/', 1)[-1] for m in group['members'])
            found = len({m['slot'] for m in group['members']})
            cells = [f"{what} '{group['name']}'", members,
                     f"{found} of {group['needed']}",
                     ('Yes' if ok else 'No') + f" — {why}"]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.table.setItem(row, column, item)
        for column, width in enumerate((180, 260, 70)):
            self.table.setColumnWidth(column, width)
        self.table.itemSelectionChanged.connect(self._update)
        self.table.itemDoubleClicked.connect(lambda _item: self._accept())
        layout.addWidget(self.table, 1)
        if not self.groups:
            empty = QLabel(
                "No Linux RAID or multi-disk Btrfs members were found among "
                "the open evidence. For a controller RAID (HP, Adaptec, a "
                "motherboard RAID), use the Hardware RAID tab.")
            empty.setObjectName("wizardFieldNote")
            empty.setWordWrap(True)
            layout.addWidget(empty)

        buttons = QDialogButtonBox()
        self.assemble_button = buttons.addButton(
            "Assemble", QDialogButtonBox.AcceptRole)
        buttons.addButton(QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)
        self.resize(900, 520)
        if self.groups:
            self.table.selectRow(0)
        self.tabs.currentChanged.connect(self._update)
        self._update()

    def _selected(self):
        rows = self.table.selectionModel().selectedRows()
        return self.groups[rows[0].row()] if rows else None

    def _update(self, *_args):
        if self.tabs.currentWidget() is self.hardware:
            self.assemble_button.setEnabled(bool(self.hardware.handlers))
            return
        group = self._selected()
        self.assemble_button.setEnabled(
            group is not None and readable(group)[0])

    def _accept(self):
        if self.tabs.currentWidget() is self.hardware:
            from trace_app.core import hwraid
            try:
                self.group = self.hardware.group()
            except hwraid.RaidError as exc:
                self.hardware.status.setText(f"Not assembled: {exc}")
                return
            self.accept()
            return
        group = self._selected()
        if group is not None and readable(group)[0]:
            self.group = group
            self.accept()

    def done(self, result):
        self.hardware.stop()
        super().done(result)


def choose_group(groups, names=None, parent=None, handlers=None):
    """Run the dialog: the chosen group, or None."""
    dialog = AssembleDialog(groups, names, parent, handlers)
    if dialog.exec() == QDialog.Accepted:
        return dialog.group
    return None
