"""The evidence a case is about to take in: chosen, checked, described.

The Evidence page of the New Case and Add Evidence wizards. Each item the
examiner adds -- by button or by dropping files and folders on the list --
is opened on a thread (core/evidence_probe.py) and its row says what it is:
ready, ready with something to know first (an encrypted volume, stored
hashes), or unreadable and why. Unreadable items are listed so the examiner
sees the reason, and are not added.

Selecting a row shows its custody details -- exhibit number, description,
acquired by, acquired on -- filled from the image's own header where it has
one, and marked so. They are what the report states about the evidence.
"""

import logging
import os
import re

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QFileDialog,
                               QFormLayout, QFrame, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QPushButton, QSplitter,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from trace_app.core import evidence_probe
from trace_app.core.case import EVIDENCE_DETAILS
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui import icons
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate

logger = logging.getLogger('TRACE.EvidenceIntake')

#: Disk images, then logical evidence -- the file dialog's filter, here so
#: the wizard and quick triage's File menu offer the same formats.
DISK_IMAGE_PATTERNS = ("*.e01", "*.E01", "*.ex01", "*.Ex01", "*.s01", "*.S01",
                       "*.aff4", "*.AFF4",
                       "*.raw", "*.RAW", "*.img", "*.IMG", "*.dd", "*.DD",
                       "*.iso", "*.ISO", "*.000", "*.001", "*.dmg",
                       "*.DMG", "*.hdd", "*.HDD", "*.hds",
                       "*.sparse", "*.sparseimage", "*.vmdk", "*.VMDK",
                       "*.vhd", "*.VHD", "*.vhdx", "*.VHDX", "*.qcow2",
                       "*.QCOW2", "*.qcow")
LOGICAL_PATTERNS = ("*.ad1", "*.AD1", "*.l01", "*.L01", "*.lx01", "*.Lx01",
                    "*.zip", "*.ZIP", "*.tar", "*.tgz", "*.tar.gz",
                    "*.tar.bz2", "*.tar.xz")
EVIDENCE_FILE_FILTER = ";;".join((
    "All Evidence ({})".format(" ".join(DISK_IMAGE_PATTERNS
                                        + LOGICAL_PATTERNS)),
    "Disk Images ({})".format(" ".join(DISK_IMAGE_PATTERNS)),
    "Logical Evidence: AD1, L01, ZIP, TAR ({})".format(
        " ".join(LOGICAL_PATTERNS)),
    "All Files (*)"))

#: Second and later segments of a segmented image: they are read with the
#: first, so selecting every segment adds the image once.
_LATER_SEGMENT = re.compile(
    r'\.(?:e|ex|s|l|lx)(?:0[2-9]|[1-9][0-9])$|\.(?:00[2-9]|0[1-9][0-9]|'
    r'[1-9][0-9]{2})$|\.ad(?:[2-9]|[1-9][0-9]+)$', re.IGNORECASE)

CHECKING = 'checking'
_STATUS_ICONS = {evidence_probe.OK: icons.SUCCESS,
                 evidence_probe.NOTES: icons.ALERT,
                 evidence_probe.ERROR: icons.ERROR,
                 CHECKING: icons.REFRESH}
_STATUS_TEXT = {evidence_probe.OK: "Ready",
                evidence_probe.NOTES: "Ready — see notes",
                evidence_probe.ERROR: "Cannot be read",
                CHECKING: "Checking…"}

#: Probes still running when their page closed: kept referenced until they
#: end, since a QThread destroyed while it runs takes the process with it.
_ORPHANS = set()


def _key(path):
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def is_later_segment(path):
    # A split raw image numbered from .000 has .001 as its second part.
    if path.lower().endswith('.001') and \
            os.path.exists(path[:-4] + '.000'):
        return True
    return bool(_LATER_SEGMENT.search(path))


class ProbeWorker(QThread):
    """Opens one item off the UI thread (ImageHandler can take seconds on a
    large or remote image)."""

    probed = Signal(str, dict)

    def __init__(self, path):
        super().__init__()
        self.path = path

    def run(self):
        try:
            result = evidence_probe.probe(self.path)
        except Exception as exc:          # probe() is not meant to raise
            logger.exception("Probe of %s failed", self.path)
            result = {'status': evidence_probe.ERROR, 'error': str(exc)}
        self.probed.emit(self.path, result)


class EvidenceIntake(QWidget):
    """The list of evidence to take in, with each item's details."""

    #: Items, their state or their details changed.
    changed = Signal()

    COLUMNS = ['', 'Name', 'Format', 'Size', 'Contents', 'Exhibit']

    def __init__(self, parent=None, existing=None):
        """`existing`: [(path, name)] already in the case -- shown greyed,
        for context, and refused if added again."""
        super().__init__(parent)
        self.setObjectName("evidenceIntake")
        self.setAcceptDrops(True)
        self.items = []
        self._existing = {_key(path): name for path, name in existing or ()}
        self._workers = {}
        self._filling = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(0)
        self.add_file_button = QPushButton("Add Image or File...")
        self.add_file_button.setObjectName("intakeButton")
        self.add_file_button.clicked.connect(self.choose_files)
        self.add_folder_button = QPushButton("Add Folder...")
        self.add_folder_button.setObjectName("intakeButton")
        self.add_folder_button.setToolTip(
            "A folder of collected files (KAPE, Velociraptor, UAC), an "
            "extraction or an iPhone backup: read in place, never written "
            "to.")
        self.add_folder_button.clicked.connect(self.choose_folder)
        self.disk_button = QPushButton("Add Disk...")
        self.disk_button.setObjectName("intakeButton")
        self.disk_button.setToolTip(
            "A disk attached to this computer, read live and read-only "
            "(asks for administrator rights). A preview, not an image.")
        self.disk_button.clicked.connect(self.choose_disk)
        self.remove_button = QPushButton("Remove")
        self.remove_button.setObjectName("intakeButton")
        self.remove_button.clicked.connect(self.remove_selected)
        for button in (self.add_file_button, self.add_folder_button,
                       self.disk_button, self.remove_button):
            # Never narrower than its text: a squeezed row clipped it.
            button.setMinimumWidth(button.sizeHint().width())
            buttons.addWidget(button)
        buttons.addStretch(1)
        hint = QLabel("or drop files and folders on the list")
        hint.setObjectName("intakeHint")
        hint.setWordWrap(True)
        buttons.addWidget(hint)
        layout.addLayout(buttons)

        splitter = QSplitter(Qt.Vertical)
        splitter.setObjectName("intakeSplitter")
        splitter.setChildrenCollapsible(False)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setObjectName("intakeTable")
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setItemDelegate(NoFocusDelegate(self.table))
        self.table.setWordWrap(False)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        self.table.setColumnWidth(0, 30)
        # Contents takes what is left; the rest are sized to what they hold.
        for column, width in ((1, 190), (2, 160), (3, 80), (5, 90)):
            header.setSectionResizeMode(column, QHeaderView.Interactive)
            self.table.setColumnWidth(column, width)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.empty_label = QLabel(
            "No evidence yet. Add disk images (E01, dd, VMDK, VHDX, DMG…), "
            "logical images (AD1, L01, ZIP, TAR) or folders.")
        self.empty_label.setObjectName("intakeEmpty")
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setWordWrap(True)
        table_box = QWidget()
        table_layout = QVBoxLayout(table_box)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.addWidget(self.table)
        table_layout.addWidget(self.empty_label)
        splitter.addWidget(table_box)
        splitter.addWidget(self._build_details())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)

        self.message = QLabel()
        self.message.setObjectName("wizardMessage")
        self.message.setWordWrap(True)
        self.message.setVisible(False)
        layout.addWidget(self.message)

        self.verify_box = QCheckBox(
            "Verify image hashes after creating (runs in the background)")
        self.verify_box.setObjectName("intakeVerify")
        self.verify_box.setChecked(True)
        self.verify_box.setToolTip(
            "Hash each image and compare with the hashes it stores (E01, "
            "AD1); where it stores none, the hashes become the baseline every "
            "later check compares with. The result is in Case ▸ Verification "
            "history and the report.")
        layout.addWidget(self.verify_box)

        for path, name in existing or ():
            self._add_row({'path': path, 'existing': True, 'name': name,
                           'result': None, 'details': {}})
        self._refresh()

    def _build_details(self):
        frame = QFrame()
        frame.setObjectName("intakeDetails")
        outer = QVBoxLayout(frame)
        outer.setContentsMargins(12, 10, 12, 10)
        outer.setSpacing(6)
        self.details_title = QLabel("Select an item to see and record its "
                                    "details.")
        self.details_title.setObjectName("intakeDetailsTitle")
        self.details_title.setWordWrap(True)
        outer.addWidget(self.details_title)
        self.details_path = QLabel()
        self.details_path.setObjectName("intakeDetailsPath")
        self.details_path.setWordWrap(True)
        self.details_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        outer.addWidget(self.details_path)
        self.details_notes = QLabel()
        self.details_notes.setObjectName("intakeDetailsNotes")
        self.details_notes.setWordWrap(True)
        outer.addWidget(self.details_notes)

        self.form_widget = QWidget()
        self.form_widget.setObjectName("intakeDetailsForm")
        form = QFormLayout(self.form_widget)
        form.setContentsMargins(0, 4, 0, 0)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(6)
        self.fields = {}
        self.field_hints = {}
        placeholders = {'exhibit_number': "e.g. JW-01",
                        'description': "e.g. Laptop HDD, Dell Latitude, "
                                       "S/N 4XK2…",
                        'acquired_by': "Who imaged it",
                        'acquired_on': "When, as recorded (e.g. 2026-09-30 "
                                       "14:05 UTC)"}
        for key, label in EVIDENCE_DETAILS.items():
            field = QLineEdit()
            field.setObjectName("intakeField")
            field.setPlaceholderText(placeholders.get(key, ''))
            field.textEdited.connect(
                lambda text, key=key: self._field_edited(key, text))
            hint = QLabel()
            hint.setObjectName("intakeFieldHint")
            # The same width whether it says anything or not, so the fields
            # line up.
            hint.setFixedWidth(120)
            row = QHBoxLayout()
            row.setSpacing(8)
            row.addWidget(field, 1)
            row.addWidget(hint)
            form.addRow(f"{label}:", row)
            self.fields[key] = field
            self.field_hints[key] = hint
        outer.addWidget(self.form_widget)
        outer.addStretch(1)
        self.form_widget.setVisible(False)
        return frame

    # --- adding --------------------------------------------------------------

    def choose_files(self):
        from trace_app.core import settings
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Add evidence", settings.user('case_folder') or '',
            EVIDENCE_FILE_FILTER)
        if paths:
            self.add_paths(paths)

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Add an evidence "
                                                        "folder")
        if folder:
            self.add_paths([folder])

    def choose_disk(self):
        from trace_app.ui.dialogs.live_disk import choose_live_disk
        device = choose_live_disk(self)
        if device:
            self.add_paths([device])

    def add_paths(self, paths):
        """Add items and start checking each. Duplicates and later segments
        of an image are skipped, and the message says so."""
        skipped, segments = [], []
        from trace_app.core.live_disk import is_device_path
        for path in paths:
            if not is_device_path(path):
                path = os.path.normpath(path)
            key = _key(path)
            if key in self._existing:
                skipped.append(f"{os.path.basename(path)} is already in the "
                               f"case")
                continue
            if any(_key(item['path']) == key for item in self.items):
                skipped.append(f"{os.path.basename(path)} is already listed")
                continue
            if os.path.isfile(path) and is_later_segment(path):
                segments.append(os.path.basename(path))
                continue
            item = {'path': path, 'existing': False,
                    'name': os.path.basename(path.rstrip('/\\')) or path,
                    'result': None, 'details': {}, 'from_header': set()}
            self._add_row(item)
            self._start_probe(item)
        notes = []
        if segments:
            notes.append(f"{len(segments)} later segment"
                         f"{'s' if len(segments) != 1 else ''} skipped "
                         f"({', '.join(segments[:3])}"
                         f"{'…' if len(segments) > 3 else ''}): each is read "
                         f"with its first segment.")
        notes += skipped
        self._say(' '.join(n if n.endswith('.') else n + '.' for n in notes))
        self._refresh()
        if self.items and not self.table.selectedItems():
            self.table.selectRow(self.table.rowCount() - 1)

    def _start_probe(self, item):
        worker = ProbeWorker(item['path'])
        worker.probed.connect(self._probed)
        worker.finished.connect(lambda w=worker: self._worker_done(w))
        self._workers[item['path']] = worker
        worker.start()

    def _worker_done(self, worker):
        self._workers.pop(worker.path, None)
        _ORPHANS.discard(worker)
        worker.deleteLater()

    def _probed(self, path, result):
        item = next((i for i in self.items if i['path'] == path), None)
        if item is None:              # removed while it was checked
            return
        item['result'] = result
        if result.get('name'):
            item['name'] = result['name']
        # The image's own record, unless the examiner has typed already.
        for key, value in (result.get('custody') or {}).items():
            if not item['details'].get(key):
                item['details'][key] = value
                item['from_header'].add(key)
        self._update_row(item)
        if self._selected_item() is item:
            self._show_details(item)
        self._refresh()

    def remove_selected(self):
        rows = sorted({index.row() for index in
                       self.table.selectionModel().selectedRows()},
                      reverse=True)
        for row in rows:
            item = self._item_at(row)
            if item is None or item.get('existing'):
                continue
            self.items.remove(item)
            self.table.removeRow(row)
        self._say('')
        self._refresh()

    # --- what the page reads back --------------------------------------------

    def new_items(self):
        return [i for i in self.items if not i.get('existing')]

    def pending(self):
        """Items still being checked."""
        return [i for i in self.new_items() if i['result'] is None]

    def unreadable(self):
        return [i for i in self.new_items() if i['result'] is not None and
                i['result'].get('status') == evidence_probe.ERROR]

    def usable(self):
        """Checked items that can join the case, as the case will take
        them: {path, display_name, details, result}."""
        out = []
        for item in self.new_items():
            result = item['result']
            if result is None or result.get('status') == evidence_probe.ERROR:
                continue
            out.append({'path': item['path'], 'display_name': item['name'],
                        'details': {k: v for k, v in item['details'].items()
                                    if v},
                        'result': result})
        return out

    def total_bytes(self):
        return sum((i['result'] or {}).get('size') or 0
                   for i in self.new_items())

    def verify_after(self):
        return self.verify_box.isChecked()

    def stop(self):
        """The page is closing: running probes are left to finish on their
        own (they only open and close the image) and forgotten."""
        for worker in list(self._workers.values()):
            try:
                worker.probed.disconnect(self._probed)
            except (RuntimeError, TypeError):
                pass
            _ORPHANS.add(worker)
        self._workers.clear()

    # --- the table -------------------------------------------------------------

    def _add_row(self, item):
        if not item.get('existing'):
            self.items.append(item)
        else:
            self.items.insert(0, item)
        row = self.table.rowCount() if not item.get('existing') else 0
        self.table.insertRow(row)
        for column in range(len(self.COLUMNS)):
            self.table.setItem(row, column, QTableWidgetItem(''))
        self._update_row(item, row)

    def _row_of(self, item):
        for row in range(self.table.rowCount()):
            if self._item_at(row) is item:
                return row
        return -1

    def _item_at(self, row):
        cell = self.table.item(row, 1)
        if cell is None:
            return None
        path = cell.data(Qt.UserRole)
        return next((i for i in self.items if i['path'] == path), None)

    def _update_row(self, item, row=None):
        row = self._row_of(item) if row is None else row
        if row < 0:
            return
        result = item['result'] or {}
        if item.get('existing'):
            status_icon, tip = icons.CASE, "Already in this case."
            values = [item['name'], 'In the case', '', '', '']
        else:
            status = result.get('status') or CHECKING
            status_icon = _STATUS_ICONS[status]
            tip = _STATUS_TEXT[status]
            if status == evidence_probe.ERROR:
                tip = f"{tip}: {result.get('error') or ''}"
            elif result.get('notes'):
                tip = f"{tip}\n" + '\n'.join(result['notes'])
            size = result.get('size')
            values = [item['name'],
                      result.get('format') or evidence_probe.format_name(
                          item['path']),
                      FileSystemUtils.get_readable_size(size)
                      if size else '—' if result else '',
                      (result.get('contents') if status != evidence_probe.ERROR
                       else result.get('error')) if result else 'Checking…',
                      item['details'].get('exhibit_number') or '']
        icon_cell = self.table.item(row, 0)
        icon_cell.setIcon(icons.icon(status_icon))
        icon_cell.setToolTip(tip)
        for column, value in enumerate(values, start=1):
            cell = self.table.item(row, column)
            cell.setText(str(value))
            cell.setToolTip(item['path'] if column == 1 else str(value))
            cell.setData(Qt.UserRole, item['path'])
            flags = Qt.ItemIsSelectable | Qt.ItemIsEnabled
            if item.get('existing'):
                flags = Qt.ItemIsSelectable
            cell.setFlags(flags)
        icon_cell.setFlags(Qt.ItemIsSelectable | (
            Qt.ItemIsEnabled if not item.get('existing') else Qt.NoItemFlags))

    def _selected_item(self):
        rows = self.table.selectionModel().selectedRows() \
            if self.table.selectionModel() else []
        if len(rows) != 1:
            return None
        return self._item_at(rows[0].row())

    def _selection_changed(self):
        self._show_details(self._selected_item())
        self.remove_button.setEnabled(any(
            (self._item_at(i.row()) or {}).get('existing') is False
            for i in self.table.selectionModel().selectedRows()))

    def _show_details(self, item):
        self._filling = True
        try:
            if item is None or item.get('existing'):
                self.details_title.setText(
                    "Already in the case — its details are in Case ▸ "
                    "Properties." if item else
                    "Select an item to see and record its details.")
                self.details_path.setText(item['path'] if item else '')
                self.details_notes.setText('')
                self.form_widget.setVisible(False)
                return
            result = item['result'] or {}
            self.details_title.setText(
                f"<b>{_html(item['name'])}</b> — "
                f"{_html(result.get('format') or 'checking…')}")
            self.details_path.setText(item['path'])
            if result.get('status') == evidence_probe.ERROR:
                self.details_notes.setText(
                    f"Cannot be read: {_html(result.get('error') or '')} "
                    f"It will not be added.")
                self.details_notes.setProperty('state', 'error')
            else:
                notes = list(result.get('notes') or ())
                self.details_notes.setText('<br>'.join(_html(n)
                                                       for n in notes))
                self.details_notes.setProperty('state',
                                               'notes' if notes else '')
            self.details_notes.style().unpolish(self.details_notes)
            self.details_notes.style().polish(self.details_notes)
            self.form_widget.setVisible(
                result.get('status') != evidence_probe.ERROR)
            for key, field in self.fields.items():
                field.setText(item['details'].get(key, ''))
                self.field_hints[key].setText(
                    "from image header" if key in item['from_header'] else '')
        finally:
            self._filling = False

    def _field_edited(self, key, text):
        if self._filling:
            return
        item = self._selected_item()
        if item is None or item.get('existing'):
            return
        item['details'][key] = text
        item['from_header'].discard(key)
        self.field_hints[key].setText('')
        if key == 'exhibit_number':
            self._update_row(item)
        self.changed.emit()

    def _say(self, text):
        self.message.setText(text)
        self.message.setVisible(bool(text))

    def _refresh(self):
        has_rows = self.table.rowCount() > 0
        self.table.setVisible(has_rows)
        self.empty_label.setVisible(not has_rows)
        self.remove_button.setEnabled(bool(self.new_items()) and bool(
            self.table.selectedItems()))
        self.changed.emit()

    # --- drag and drop ------------------------------------------------------------

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and any(
                url.isLocalFile() for url in event.mimeData().urls()):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        self.dragEnterEvent(event)

    def dropEvent(self, event):
        paths = [url.toLocalFile() for url in event.mimeData().urls()
                 if url.isLocalFile()]
        if paths:
            event.acceptProposedAction()
            self.add_paths(paths)


def _html(text):
    import html
    return html.escape(str(text or ''))
