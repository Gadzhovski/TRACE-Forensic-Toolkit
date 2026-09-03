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
                               QTableWidgetItem, QVBoxLayout, QWidget)

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

        self.evidence_table = QTableWidget()
        self.evidence_table.setObjectName("caseEvidenceTable")
        self.evidence_table.setColumnCount(5)
        self.evidence_table.setHorizontalHeaderLabels(
            ['Name', 'Status', 'MD5', 'Size', 'Path'])
        self.evidence_table.verticalHeader().setVisible(False)
        self.evidence_table.verticalHeader().setDefaultSectionSize(
            TABLE_ROW_HEIGHT)
        self.evidence_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.evidence_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.evidence_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        layout.addWidget(self.evidence_table)

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
            self.evidence_table.setVisible(False)
            return

        self.details.setVisible(True)
        self.evidence_heading.setVisible(True)
        self.evidence_table.setVisible(True)

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

    def _fill_evidence(self):
        evidence = self.case.evidence()
        self.evidence_table.setRowCount(len(evidence))
        self.evidence_heading.setText(
            f"Evidence ({len(evidence)})" if evidence else "Evidence (none)")

        for row, item in enumerate(evidence):
            status = item.get('last_status') or STATUS_PENDING
            size = item.get('size')
            values = [
                item.get('display_name') or os.path.basename(item['path']),
                STATUS_TEXT.get(status, status),
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

        fit_columns(self.evidence_table, {4: 380})

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
