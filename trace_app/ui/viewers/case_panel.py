"""The Case tab: what this investigation is, and what evidence it holds.

Read-only for now. It exists as much for what comes next as for what it shows
today: notes, bookmarks and findings all belong on this panel, and giving them
a home before they are written keeps each one a view rather than a new
persistence layer.

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
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        self.headline = QLabel()
        self.headline.setObjectName("caseHeadline")
        self.headline.setWordWrap(True)
        layout.addWidget(self.headline)

        self.details = PropertyTable()
        self.details.setObjectName("caseDetailsTable")
        layout.addWidget(self.details)

        self.evidence_heading = QLabel("Evidence")
        self.evidence_heading.setObjectName("caseSectionHeading")
        layout.addWidget(self.evidence_heading)

        # Evidence, its verification history, and the audit trail are three
        # views of the same question -- "can this evidence be relied on" --
        # so they live as tabs rather than three stacked tables nobody can
        # read at this dock height.
        self.tabs = QTabWidget()
        self.tabs.setObjectName("caseTabs")
        layout.addWidget(self.tabs)

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
        self.tabs.addTab(self.evidence_table, "Evidence")

        self.history_table = self._make_table(
            "caseHistoryTable",
            ['When (UTC)', 'Evidence', 'Result', 'Algorithm', 'Detail'])
        self.tabs.addTab(self.history_table, "Verification history")

        self.activity_table = self._make_table(
            "caseActivityTable", ['When (UTC)', 'Action', 'Detail'])
        self.tabs.addTab(self.activity_table, "Activity log")

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
            self.details.setVisible(False)
            self.evidence_heading.setVisible(False)
            self.tabs.setVisible(False)
            return

        self.details.setVisible(True)
        self.evidence_heading.setVisible(True)
        self.tabs.setVisible(True)

        metadata = self.case.metadata
        name = metadata.get('name', '(unnamed)')
        number = metadata.get('number', '')
        self.headline.setText(f"{name} · {number}" if number else name)

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
        self.evidence_heading.setText(
            f"Evidence ({len(evidence)})" if evidence else "Evidence (none)")

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
