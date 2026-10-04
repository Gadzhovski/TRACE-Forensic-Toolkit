"""The Case tab: what this investigation is, and what evidence it holds.

Laid out for the dock it actually lives in. The Utils panel is around 220px
tall, because the listing is where the investigation happens and should keep
the window; a panel that asks for more than that gets three widgets none of
which can be read.

So: one line of identity at the top, and everything else behind tabs, with
exactly one table on screen taking all the remaining height. The case's details
are a tab of their own rather than a permanent block, since they are read once
and the evidence is read constantly.

Shows nothing useful in quick triage, and says so plainly rather than
presenting an empty table.
"""

import logging
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QHeaderView, QLabel, QTableWidget,
                               QTableWidgetItem, QTabWidget, QVBoxLayout,
                               QWidget)

from trace_app.core.case import (STATUS_CHANGED, STATUS_MISSING,
                                 STATUS_PENDING, STATUS_UNHASHED,
                                 STATUS_VERIFIED)
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui.widgets.property_table import PropertyTable
from trace_app.ui.widgets.table_columns import fit_columns

logger = logging.getLogger('TRACE.CasePanel')

#: How each evidence status reads to an examiner. The wording matters: a file
#: that is present but no longer matches its recorded hash is the one finding
#: here that changes what an examiner does next, so it does not get a bare
#: one-word label.
STATUS_TEXT = {
    STATUS_VERIFIED: "Verified",
    STATUS_PENDING: "Not yet hashed",
    STATUS_UNHASHED: "No hash recorded",
    STATUS_MISSING: "MISSING from its recorded location",
    STATUS_CHANGED: "CHANGED since it was added",
}


class CasePanel(QWidget):
    """Case metadata and its evidence, with hash status."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None

        layout = QVBoxLayout(self)
        # Tight margins: this panel lives in a dock about 220px tall, and
        # every pixel spent on padding is a row of evidence not shown.
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(4)

        # One line, not a block. The case's name and number are what an
        # examiner needs to see at a glance; everything else about the case is
        # on the Details tab, where it costs no height until asked for.
        self.headline = QLabel()
        self.headline.setObjectName("caseHeadline")
        self.headline.setWordWrap(False)
        self.headline.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.headline)

        # Everything else is a tab, so exactly one table is on screen and it
        # gets all the height there is.
        self.tabs = QTabWidget()
        self.tabs.setObjectName("caseTabs")
        self.tabs.setDocumentMode(True)
        # No base line: in document mode Qt rules one along the top of the
        # tab row, a stray line no other tab strip in TRACE has.
        self.tabs.tabBar().setDrawBase(False)
        layout.addWidget(self.tabs, 1)

        self.details = PropertyTable()
        self.details.setObjectName("caseDetailsTable")
        self.details.setMinimumHeight(TABLE_ROW_HEIGHT * 2)

        # Kept so refresh() can still address it; the heading itself is now
        # the tab label.
        self.evidence_heading = QLabel()
        self.evidence_heading.setVisible(False)

        self.evidence_table = QTableWidget()
        self.evidence_table.setObjectName("caseEvidenceTable")
        self.evidence_table.setColumnCount(7)
        self.evidence_table.setHorizontalHeaderLabels(
            ['Name', 'Status', 'Access', 'Last checked', 'MD5', 'Size',
             'Path'])
        self.evidence_table.verticalHeader().setVisible(False)
        self.evidence_table.verticalHeader().setDefaultSectionSize(
            TABLE_ROW_HEIGHT)
        self.evidence_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.evidence_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.evidence_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        self.evidence_table.setMinimumHeight(TABLE_ROW_HEIGHT * 2)
        self.tabs.addTab(self.evidence_table, "Evidence")

        self.history_table = self._make_table(
            "caseHistoryTable",
            ['When (UTC)', 'Evidence', 'Result', 'Algorithm', 'Detail'])
        self.tabs.addTab(self.history_table, "Verification history")

        self.activity_table = self._make_table(
            "caseActivityTable", ['When (UTC)', 'Action', 'Detail'])
        self.tabs.addTab(self.activity_table, "Activity log")

        # Last, because it is the tab an examiner opens least often.
        self.tabs.addTab(self.details, "Details")

        self.set_case(None)

    # --- population -------------------------------------------------------

    def set_case(self, case):
        """Point the panel at a case, or at None for quick triage."""
        self.case = case
        self.refresh()

    def refresh(self):
        """Redraw from the case. Safe to call when there is no case."""
        if self.case is None:
            self.headline.setText(
                "Quick triage — no case is open.\n\n"
                "Nothing is saved between sessions. Start a case from "
                "File ▸ New Case to keep evidence, hashes and findings "
                "together.")
            self.tabs.setVisible(False)
            return

        self.tabs.setVisible(True)

        metadata = self.case.metadata
        name = metadata.get('name', '(unnamed)')
        number = metadata.get('number', '')
        examiner = metadata.get('examiner', '')

        # Everything identifying on one line, since that is all the height
        # there is for it.
        parts = [f"<b>{name}</b>"]
        if number:
            parts.append(number)
        if examiner:
            parts.append(examiner)
        self.headline.setText("  ·  ".join(parts))
        self.headline.setToolTip(metadata.get('description') or '')

        rows = [
            ("Case name", name),
            ("Case number", number or "—"),
            ("Examiner", metadata.get('examiner') or "—"),
            ("Description", metadata.get('description') or "—"),
            ("Created", metadata.get('created_utc') or "—"),
            ("Case folder", self.case.folder),
        ]
        self.details.set_rows(rows)

        self._fill_evidence()
        self._fill_history()
        self._fill_activity()

    def _fill_evidence(self):
        evidence = self.case.evidence()
        self.evidence_table.setRowCount(len(evidence))
        # The count belongs on the tab, where it is visible whichever tab is
        # open, rather than on a heading that costs a line of height.
        self.tabs.setTabText(0, f"Evidence ({len(evidence)})")

        for row, item in enumerate(evidence):
            status = item.get('last_status') or STATUS_PENDING
            size = item.get('size')
            checked = item.get('verified_utc') or '—'
            values = [
                item.get('display_name') or os.path.basename(item['path']),
                STATUS_TEXT.get(status, status),
                # TRACE never writes to evidence; this records what the
                # examiner declared, which is what a report has to state.
                'Read-only' if item.get('read_only', 1) else 'Writable',
                checked,
                (item.get('md5') or '—'),
                f"{size:,}" if size is not None else '—',
                item['path'],
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 1 and status in (STATUS_MISSING, STATUS_CHANGED):
                    # Flagged in the text as well as any styling, so the
                    # meaning survives a screenshot or a colour-blind reader.
                    cell.setToolTip(
                        "This evidence no longer matches what the case "
                        "recorded. Investigate before relying on it.")
                self.evidence_table.setItem(row, column, cell)

        fit_columns(self.evidence_table, {6: 380})

    @staticmethod
    def _make_table(object_name, headers):
        """A read-only table shaped like the evidence one."""
        table = QTableWidget()
        # Small enough to fit a short dock and scroll, rather than demanding a
        # height the Utils panel does not have and pushing everything else off
        # screen.
        table.setMinimumHeight(TABLE_ROW_HEIGHT * 2)
        table.setObjectName(object_name)
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        return table

    def _fill_history(self):
        """Every verification ever run, newest first.

        The history is the chain of custody: "this matched when it was added
        and again last Tuesday" is a different and far more useful claim than
        "this matches now", and only the history can support it.
        """
        names = {row['id']: (row.get('display_name')
                             or os.path.basename(row['path']))
                 for row in self.case.evidence()}
        history = self.case.verifications()
        self.history_table.setRowCount(len(history))

        for row, entry in enumerate(history):
            status = entry.get('status') or ''
            values = [
                entry.get('utc') or '',
                names.get(entry.get('evidence_id'), '—'),
                STATUS_TEXT.get(status, status),
                (entry.get('algorithm') or '—').upper(),
                entry.get('detail') or '',
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if column == 2 and status in (STATUS_MISSING, STATUS_CHANGED):
                    cell.setToolTip(
                        "This check found the evidence was not as the case "
                        "recorded it.")
                self.history_table.setItem(row, column, cell)

        fit_columns(self.history_table, {4: 420})

    def _fill_activity(self):
        """The examination log: what was done to this case, and when."""
        entries = self.case.activity(limit=500)
        self.activity_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for column, value in enumerate((entry.get('utc') or '',
                                            entry.get('action') or '',
                                            entry.get('detail') or '')):
                self.activity_table.setItem(
                    row, column, QTableWidgetItem(str(value)))
        fit_columns(self.activity_table, {2: 420})

    # --- adapter contract -------------------------------------------------

    def display_case(self, data):
        """Called by the viewer dispatch; the panel ignores the selected file.

        A case is a property of the session, not of whichever file happens to
        be selected, so there is nothing per-artifact to show here yet. Notes
        and bookmarks will change that.
        """
        self.refresh()

    def clear_content(self):
        # The case outlives any one file selection, so there is nothing to
        # clear when the selection changes.
        pass
