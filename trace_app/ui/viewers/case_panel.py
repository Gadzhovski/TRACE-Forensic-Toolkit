"""The Case tab: what this investigation is, and what evidence it holds.

Laid out for the dock it lives in, which is short: the case itself on a
card at the left -- name, number, examiner, what it is about, when it was
opened, where it is kept, and how its evidence stands -- with its actions
under it; beside it the tables, one at a time: the evidence, every
verification ever run (the chain of custody), and the activity log.

Evidence rows say their status in colour as well as words (a changed or
missing image is the one finding here that changes what an examiner does
next), and carry their actions on a right-click: verify, edit the exhibit
details, copy a hash or the path, open the folder.

In quick triage there is no case, and the tab says so plainly rather than
presenting empty tables.
"""

import datetime
import logging
import os

from PySide6.QtCore import QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QApplication, QDialog,
                               QDialogButtonBox, QFormLayout, QFrame,
                               QGridLayout, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMenu, QPushButton, QScrollArea,
                               QTableWidget, QTableWidgetItem, QTabWidget,
                               QVBoxLayout, QWidget)

from trace_app.core.case import (EVIDENCE_DETAILS, STATUS_BASELINE,
                                 STATUS_CHANGED, STATUS_LIVE, STATUS_MISSING,
                                 STATUS_PENDING, STATUS_UNHASHED,
                                 STATUS_UNREADABLE, STATUS_VERIFIED)
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui import icons
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.table_columns import fit_columns
from trace_app.ui.widgets.context_menus import show_menu

logger = logging.getLogger('TRACE.CasePanel')

#: How each evidence status reads. A file that no longer matches its
#: recorded hash is the finding that changes what an examiner does next,
#: so it does not get a bare one-word label.
STATUS_TEXT = {
    STATUS_VERIFIED: "Verified",
    STATUS_BASELINE: "Hashed -- nothing to compare with yet",
    STATUS_PENDING: "Not yet hashed",
    STATUS_UNHASHED: "No hash recorded",
    STATUS_MISSING: "MISSING from its recorded location",
    STATUS_CHANGED: "CHANGED -- does not match what was recorded",
    STATUS_UNREADABLE: "UNREADABLE -- could not be read in full",
    STATUS_LIVE: "Read live (not verifiable)",
}
#: Statuses that mean the evidence cannot be relied on as recorded.
STATUS_TROUBLE = (STATUS_MISSING, STATUS_CHANGED, STATUS_UNREADABLE)
#: Status -> tone (virustotal.verdict_brush) and icon.
STATUS_TONE = {STATUS_VERIFIED: 'clean', STATUS_MISSING: 'malicious',
               STATUS_CHANGED: 'malicious', STATUS_UNREADABLE: 'malicious',
               STATUS_LIVE: 'suspicious', STATUS_BASELINE: 'suspicious'}
STATUS_ICON = {STATUS_VERIFIED: icons.VERIFY_OK, STATUS_MISSING: icons.ERROR,
               STATUS_CHANGED: icons.ERROR, STATUS_UNREADABLE: icons.ERROR,
               STATUS_LIVE: icons.ALERT, STATUS_BASELINE: icons.VERIFY}
#: Evidence table columns.
EVIDENCE_COLUMNS = ['Name', 'Exhibit', 'Status', 'Last checked', 'Size',
                    'Contains', 'MD5', 'SHA-256', 'Path']


def format_utc(text, seconds=False):
    """'2026-10-06T13:15:28+00:00' as '2026-10-06 13:15 UTC' (and the case's
    display zone beside it, when one is set)."""
    if not text:
        return '—'
    try:
        moment = datetime.datetime.fromisoformat(str(text).replace('Z', ''))
    except ValueError:
        return str(text)
    if moment.tzinfo is not None:
        moment = moment.astimezone(datetime.timezone.utc)
    shown = moment.strftime('%Y-%m-%d %H:%M:%S' if seconds else
                            '%Y-%m-%d %H:%M') + ' UTC'
    try:
        from trace_app.core.settings import alongside
        return alongside(shown) if seconds else shown
    except Exception:
        return shown


def short_hash(digest, keep=8):
    """'9f9f9f9f…9f9f9f9f' -- the whole digest is in the tooltip."""
    if not digest:
        return '—'
    return digest if len(digest) <= keep * 2 + 1 else \
        f"{digest[:keep]}…{digest[-keep:]}"


class EvidenceDetailsDialog(QDialog):
    """The custody details of one piece of evidence -- exhibit number,
    description, who acquired it and when -- edited after it was added.
    Every change is audited (Case.update_evidence_details)."""

    def __init__(self, case, row, parent=None):
        super().__init__(parent)
        self.case, self.row = case, row
        self.setWindowTitle("Exhibit Details")
        self.setObjectName("evidenceDetailsDialog")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        name = row.get('display_name') or os.path.basename(row['path'])
        title = QLabel(name)
        title.setObjectName("wizardTitle")
        layout.addWidget(title)
        where = QLabel(row['path'])
        where.setObjectName("settingsHint")
        where.setWordWrap(True)
        layout.addWidget(where)
        form = QFormLayout()
        self.fields = {}
        for key, label in EVIDENCE_DETAILS.items():
            field = QLineEdit(row.get(key) or '')
            self.fields[key] = field
            form.addRow(label, field)
        # The hashes it was acquired as, from the custody paperwork or the
        # imaging tool: what every verification compares with. An image
        # that stores its own (an E01) keeps those; these are checked too.
        self.hash_fields = {}
        for name, label in (('md5', "Acquisition MD5"),
                            ('sha1', "Acquisition SHA-1"),
                            ('sha256', "Acquisition SHA-256")):
            field = QLineEdit(row.get(f'stored_{name}') or '')
            field.setObjectName("hashField")
            field.setPlaceholderText("as recorded when it was acquired")
            self.hash_fields[name] = field
            form.addRow(label, field)
        layout.addLayout(form)
        if row.get('stored_source'):
            source = QLabel(f"Acquisition hashes from: {row['stored_source']}")
            source.setObjectName("settingsHint")
            source.setWordWrap(True)
            layout.addWidget(source)
        note = QLabel("Changes are written to the case's activity log, with "
                      "the old and new values.")
        note.setObjectName("settingsHint")
        note.setWordWrap(True)
        layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.Save |
                                   QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def accept(self):
        from trace_app.ui.dialogs import message
        hashes = {name: field.text().strip()
                  for name, field in self.hash_fields.items()}
        changed = any((self.row.get(f'stored_{n}') or '') != v.lower()
                      for n, v in hashes.items())
        if changed:
            try:
                self.case.set_acquisition_hashes(
                    self.row['id'], 'entered by the examiner', **hashes)
            except ValueError as exc:
                message.warning(self, "Acquisition hash", str(exc))
                return
        self.case.update_evidence_details(
            self.row['id'], **{key: field.text().strip()
                               for key, field in self.fields.items()})
        super().accept()


class CasePanel(QWidget):
    """Case metadata and its evidence, with hash status."""

    #: Rows of evidence to verify; the window queues the jobs.
    verify_requested = Signal(list)
    #: The case's own details (the Case Properties dialog).
    properties_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("casePanel")
        self.case = None
        #: row -> what the image holds ('GPT · Btrfs · Linux'), or None
        #: while it is not open; set by the window.
        self.profile_for = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # --- the case card ---
        self.card = QFrame()
        self.card.setObjectName("caseCard")
        self.card.setFixedWidth(330)
        card = QVBoxLayout(self.card)
        card.setContentsMargins(14, 10, 14, 10)
        card.setSpacing(4)
        self.title = QLabel()
        self.title.setObjectName("caseTitle")
        self.title.setWordWrap(True)
        self.title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card.addWidget(self.title)
        self.meta = QLabel()
        self.meta.setObjectName("caseMeta")
        self.meta.setWordWrap(True)
        self.meta.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card.addWidget(self.meta)
        self.description = QLabel()
        self.description.setObjectName("caseDescription")
        self.description.setWordWrap(True)
        self.description.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card.addWidget(self.description)

        facts = QGridLayout()
        facts.setContentsMargins(0, 6, 0, 0)
        facts.setHorizontalSpacing(10)
        facts.setVerticalSpacing(3)
        self.facts = {}
        for row, label in enumerate(("Opened", "Evidence", "Audit trail",
                                     "Folder")):
            name = QLabel(label)
            name.setObjectName("caseFactLabel")
            value = QLabel()
            value.setObjectName("caseFactValue")
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            facts.addWidget(name, row, 0, Qt.AlignTop)
            facts.addWidget(value, row, 1)
            self.facts[label] = value
        facts.setColumnStretch(1, 1)
        card.addLayout(facts)
        card.addStretch(1)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.edit_button = QPushButton("Edit Case…")
        self.edit_button.setObjectName("caseAction")
        self.edit_button.clicked.connect(self.properties_requested.emit)
        self.verify_button = QPushButton("Verify All")
        self.verify_button.setObjectName("caseAction")
        self.verify_button.setToolTip("Check every image against the hashes "
                                      "recorded for it (runs in the "
                                      "background)")
        self.verify_button.clicked.connect(
            lambda: self.verify_requested.emit(self.case.evidence())
            if self.case else None)
        self.folder_button = QPushButton("Open Folder")
        self.folder_button.setObjectName("caseAction")
        self.folder_button.clicked.connect(
            lambda: self._open_folder(self.case.folder) if self.case
            else None)
        for button in (self.edit_button, self.verify_button,
                       self.folder_button):
            actions.addWidget(button)
        actions.addStretch(1)
        card.addLayout(actions)

        scroll = QScrollArea()
        scroll.setObjectName("caseCardScroll")
        scroll.setWidget(self.card)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setFixedWidth(332)
        self.card_scroll = scroll
        layout.addWidget(scroll)

        # --- the tables ---
        self.tabs = QTabWidget()
        self.tabs.setObjectName("caseTabs")
        self.tabs.setDocumentMode(True)
        self.tabs.tabBar().setDrawBase(False)
        self.filter = QLineEdit()
        self.filter.setObjectName("caseFilter")
        self.filter.setPlaceholderText("Filter…")
        self.filter.setClearButtonEnabled(True)
        self.filter.setFixedWidth(220)
        self.filter.textChanged.connect(self._apply_filter)
        self.tabs.setCornerWidget(self.filter, Qt.TopRightCorner)
        self.tabs.currentChanged.connect(lambda _i: self._apply_filter())
        # Inset as the Triage tab's tables are.
        self.tables = QWidget()
        inset = QVBoxLayout(self.tables)
        inset.setContentsMargins(6, 4, 6, 4)
        inset.addWidget(self.tabs)
        layout.addWidget(self.tables, 1)

        self.evidence_table = self._make_table("caseEvidenceTable",
                                               EVIDENCE_COLUMNS)
        self.evidence_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.evidence_table.customContextMenuRequested.connect(
            self._evidence_menu)
        self.evidence_table.itemDoubleClicked.connect(
            lambda item: self.edit_evidence(self._evidence_row(item.row())))
        self.tabs.addTab(self.evidence_table,
                         icons.icon(icons.CASE_PROPERTIES), "Evidence")
        self.history_table = self._make_table(
            "caseHistoryTable",
            ['When', 'Evidence', 'Result', 'Algorithm', 'Detail'])
        self.tabs.addTab(self.history_table, icons.icon(icons.VERIFY),
                         "Verification history")
        self.activity_table = self._make_table(
            "caseActivityTable", ['When', 'Action', 'Detail'])
        self.tabs.addTab(self.activity_table, icons.icon(icons.TIMELINE),
                         "Activity log")

        self.empty = QLabel(
            "Quick triage — no case is open.\n\nNothing is kept between "
            "sessions. Start a case from File ▸ New Case to keep evidence, "
            "hashes, notes and findings together.")
        self.empty.setObjectName("caseEmpty")
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.setWordWrap(True)
        layout.addWidget(self.empty, 1)

        # Kept for callers of the old layout.
        self.headline = self.title
        self.details = None

        self.set_case(None)

    @staticmethod
    def _make_table(object_name, headers):
        table = QTableWidget()
        table.setObjectName(object_name)
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setDefaultAlignment(
            Qt.AlignLeft | Qt.AlignVCenter)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setWordWrap(False)
        table.setTextElideMode(Qt.ElideMiddle)
        table.setItemDelegate(NoFocusDelegate(table))
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table.setMinimumHeight(TABLE_ROW_HEIGHT * 2)
        return table

    # --- population -------------------------------------------------------

    def set_case(self, case):
        self.case = case
        self.refresh()

    def refresh(self):
        has_case = self.case is not None
        self.card_scroll.setVisible(has_case)
        self.tables.setVisible(has_case)
        self.empty.setVisible(not has_case)
        if not has_case:
            return
        metadata = self.case.metadata
        self.title.setText(metadata.get('name') or '(unnamed case)')
        self.meta.setText('  ·  '.join(filter(None, (
            metadata.get('number'), metadata.get('examiner'),
            metadata.get('organisation')))) or 'No number or examiner set')
        description = metadata.get('description') or ''
        self.description.setText(description or "No description.")
        self.description.setProperty('empty', not description)
        self.description.style().unpolish(self.description)
        self.description.style().polish(self.description)
        self.facts["Opened"].setText(format_utc(metadata.get('created_utc')))
        folder = self.case.folder
        self.facts["Folder"].setText(self._elide(folder, 34))
        self.facts["Folder"].setToolTip(folder)
        evidence = self.case.evidence()
        self.facts["Evidence"].setText(self._evidence_summary(evidence))
        # The chain is checked every time the card is shown: an edit made
        # to case.db outside TRACE shows here, not only in a report.
        audit = self.case.verify_audit()
        self.facts["Audit trail"].setText(
            f"{audit['entries']:,} entries, chain intact" if audit['ok']
            else "DOES NOT VERIFY -- entries were changed or removed")
        self.facts["Audit trail"].setToolTip(
            f"Newest entry SHA-256: {audit['head']}" if audit['ok']
            else '\n'.join(audit['problems'][:20]))
        self.verify_button.setEnabled(bool(evidence))
        self._fill_evidence(evidence)
        self._fill_history(evidence)
        self._fill_activity()
        self._apply_filter()

    @staticmethod
    def _elide(text, keep):
        return text if len(text) <= keep else \
            f"{text[:keep // 2 - 1]}…{text[-(keep // 2):]}"

    @staticmethod
    def _evidence_summary(evidence):
        if not evidence:
            return "None yet"
        counts = {}
        for row in evidence:
            status = row.get('last_status') or STATUS_PENDING
            counts[status] = counts.get(status, 0) + 1
        parts = [f"{len(evidence)} item{'s' if len(evidence) != 1 else ''}"]
        for status in (STATUS_CHANGED, STATUS_UNREADABLE, STATUS_MISSING,
                       STATUS_VERIFIED, STATUS_BASELINE, STATUS_LIVE,
                       STATUS_UNHASHED, STATUS_PENDING):
            if counts.get(status):
                word = {STATUS_VERIFIED: 'verified',
                        STATUS_BASELINE: 'hashed, no reference',
                        STATUS_PENDING: 'not hashed',
                        STATUS_UNHASHED: 'no hash recorded',
                        STATUS_MISSING: 'MISSING',
                        STATUS_CHANGED: 'CHANGED',
                        STATUS_UNREADABLE: 'UNREADABLE',
                        STATUS_LIVE: 'live'}[status]
                parts.append(f"{counts[status]} {word}")
        return ' · '.join(parts)

    def _status_cell(self, status):
        from trace_app.ui.viewers.virustotal import verdict_brush
        cell = QTableWidgetItem(STATUS_TEXT.get(status, status))
        tone = STATUS_TONE.get(status)
        if tone:
            cell.setForeground(verdict_brush(tone))
        if status in STATUS_ICON:
            cell.setIcon(icons.icon(STATUS_ICON[status]))
        if status in STATUS_TROUBLE:
            # In the text as well as the colour, so the meaning survives a
            # screenshot or a colour-blind reader.
            cell.setToolTip("This evidence no longer matches what the case "
                            "recorded. Investigate before relying on it.")
        return cell

    def _fill_evidence(self, evidence):
        table = self.evidence_table
        table.setSortingEnabled(False)
        table.setRowCount(len(evidence))
        self.tabs.setTabText(0, f"Evidence ({len(evidence)})")
        for row, item in enumerate(evidence):
            status = item.get('last_status') or STATUS_PENDING
            size = item.get('size')
            name = item.get('display_name') or os.path.basename(item['path'])
            custody = '\n'.join(f"{label}: {item[key]}" for key, label in
                                EVIDENCE_DETAILS.items() if item.get(key))
            contents = self._contents(item)
            cells = [
                QTableWidgetItem(name),
                QTableWidgetItem(item.get('exhibit_number') or '—'),
                self._status_cell(status),
                QTableWidgetItem(format_utc(item.get('verified_utc'))),
                QTableWidgetItem(FileSystemUtils.get_readable_size(size)
                                 if size is not None else '—'),
                QTableWidgetItem(contents or '—'),
                QTableWidgetItem(short_hash(item.get('md5'))),
                QTableWidgetItem(short_hash(item.get('sha256'))),
                QTableWidgetItem(item['path']),
            ]
            cells[0].setData(Qt.UserRole, item)
            cells[0].setToolTip(custody or name)
            cells[1].setToolTip(custody)
            if size is not None:
                cells[4].setToolTip(f"{size:,} bytes")
            cells[5].setToolTip(contents or "Not read yet: the image is not "
                                            "open")
            cells[6].setToolTip(item.get('md5') or '')
            cells[7].setToolTip(item.get('sha256') or '')
            cells[8].setToolTip(item['path'])
            for column, cell in enumerate(cells):
                table.setItem(row, column, cell)
        fit_columns(table, {5: 260, 8: 360})

    def _contents(self, item):
        """What the image holds -- 'GPT · NTFS, Ext4 · Windows + Linux'
        (core/evidence_profile) -- from the window, or None."""
        if self.profile_for is None:
            return None
        try:
            return self.profile_for(item)
        except Exception as exc:
            logger.debug("No profile for %s: %s", item.get('path'), exc)
            return None

    def _evidence_row(self, index):
        item = self.evidence_table.item(index, 0)
        return item.data(Qt.UserRole) if item is not None else None

    def _fill_history(self, evidence):
        """Every verification ever run, newest first -- the chain of
        custody: "this matched when it was added and again last Tuesday"
        is a stronger claim than "this matches now"."""
        names = {row['id']: (row.get('display_name')
                             or os.path.basename(row['path']))
                 for row in evidence}
        history = self.case.verifications()
        table = self.history_table
        table.setRowCount(len(history))
        for row, entry in enumerate(history):
            status = entry.get('status') or ''
            # Evidence since removed keeps its history, under its name.
            name = names.get(entry.get('evidence_id')) or (
                f"{entry['evidence_name']} (removed)"
                if entry.get('evidence_name') else '—')
            cells = [QTableWidgetItem(format_utc(entry.get('utc'), True)),
                     QTableWidgetItem(name),
                     self._status_cell(status),
                     QTableWidgetItem((entry.get('algorithm') or '—')
                                      .upper()),
                     QTableWidgetItem(entry.get('detail') or '')]
            cells[4].setToolTip(entry.get('detail') or '')
            for column, cell in enumerate(cells):
                table.setItem(row, column, cell)
        fit_columns(table, {4: 480})

    def _fill_activity(self):
        """The examination log: what was done to this case, and when."""
        entries = self.case.activity(limit=1000)
        table = self.activity_table
        table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            detail = entry.get('detail') or ''
            cells = [QTableWidgetItem(format_utc(entry.get('utc'), True)),
                     QTableWidgetItem(entry.get('action') or ''),
                     QTableWidgetItem(detail)]
            cells[2].setToolTip(detail)
            for column, cell in enumerate(cells):
                table.setItem(row, column, cell)
        fit_columns(table, {2: 560})

    def _apply_filter(self, *_args):
        """Rows of the table in front containing the filter's text."""
        table = self.tabs.currentWidget()
        if not isinstance(table, QTableWidget):
            return
        needle = self.filter.text().strip().lower()
        for row in range(table.rowCount()):
            shown = not needle or any(
                needle in (table.item(row, column).text().lower()
                           + (table.item(row, column).toolTip() or '').lower())
                for column in range(table.columnCount())
                if table.item(row, column) is not None)
            table.setRowHidden(row, not shown)

    # --- actions ------------------------------------------------------------

    def _evidence_menu(self, point):
        index = self.evidence_table.indexAt(point)
        if not index.isValid():
            return
        row = self._evidence_row(index.row())
        if row is None:
            return
        menu = QMenu(self)
        verify = menu.addAction(icons.icon(icons.VERIFY), "Verify")
        verify.triggered.connect(lambda: self.verify_requested.emit([row]))
        edit = menu.addAction("Edit Exhibit Details…")
        edit.triggered.connect(lambda: self.edit_evidence(row))
        menu.addSeparator()
        for key, label in (('md5', "Copy MD5"), ('sha1', "Copy SHA-1"),
                           ('sha256', "Copy SHA-256")):
            action = menu.addAction(label)
            action.setEnabled(bool(row.get(key)))
            action.triggered.connect(
                lambda _c=False, k=key: QApplication.clipboard().setText(
                    row.get(k) or ''))
        copy_path = menu.addAction("Copy Path")
        copy_path.triggered.connect(
            lambda: QApplication.clipboard().setText(row['path']))
        folder = menu.addAction(icons.icon(icons.OPEN_FOLDER),
                                "Open Containing Folder")
        folder.setEnabled(os.path.exists(row['path']))
        folder.triggered.connect(
            lambda: self._open_folder(os.path.dirname(row['path'])))
        show_menu(menu, self.evidence_table.viewport().mapToGlobal(point))

    def edit_evidence(self, row):
        if row is None or self.case is None:
            return
        dialog = EvidenceDetailsDialog(self.case, row, self)
        if dialog.exec() == QDialog.Accepted:
            self.refresh()

    @staticmethod
    def _open_folder(path):
        if path and os.path.isdir(path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    # --- adapter contract -------------------------------------------------

    def display_case(self, data):
        """The case is a property of the session, not of the selected
        file: nothing per-artifact to show."""
        self.refresh()

    def clear_content(self):
        pass
