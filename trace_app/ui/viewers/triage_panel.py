"""What the analysis modules found, and the thread that finds it.

The panel is deliberately a list of findings rather than a list of files. An
examiner opening it wants "what on this image is unusual", and a table of every
file with an entropy column is not an answer to that question -- it is the same
listing again with one more column to sort by.

So: three groups, each of which is a reason to look at something. Files that
are not what they claim, files that look like random data, and files that exist
more than once.
"""

import logging

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView,
                               QLabel, QPushButton, QTableWidget,
                               QTableWidgetItem, QTabWidget, QVBoxLayout,
                               QWidget)

from trace_app.core.analysis import (MODULE_ENTROPY, MODULE_HASH, MODULE_MAGIC,
                                     analyse_evidence)
from trace_app.core.case import REPORTED_MISMATCHES, Case
from trace_app.core.image_handler import ImageHandler
from trace_app.infra.constants import CONTROL_HEIGHT, TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui.widgets.table_columns import fit_columns

logger = logging.getLogger('TRACE.Triage')


#: What each grade means, in the column beside it. The grade names are for the
#: database; this is for the person reading the table.
_WHY = {
    'suspicious': 'Executable disguised as data',
    'notable': 'Unidentifiable and random — likely encrypted',
}


class AnalysisWorker(QThread):
    """Runs the analysis modules off the UI thread."""

    progressed = Signal(int, int, str)
    finished_analysis = Signal(int, str)

    def __init__(self, image_path, case_folder, evidence_id, modules,
                 parent=None):
        super().__init__(parent)
        # Paths, not open objects: a SQLite connection belongs to the thread
        # that made it, and a pytsk3 handle opened on the UI thread reports
        # nothing useful when read from here. Both are opened again inside
        # run().
        self.image_path = image_path
        self.case_folder = case_folder
        self.evidence_id = evidence_id
        self.modules = list(modules)
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        case = None
        handler = None
        try:
            case = Case.open(self.case_folder)
            handler = ImageHandler(self.image_path)
            if not handler.load_image():
                raise RuntimeError(
                    f"Could not open {self.image_path} for analysis.")
            count = analyse_evidence(
                handler, case, self.evidence_id, self.modules,
                progress=lambda done, total, path:
                    self.progressed.emit(done, total, path),
                should_stop=lambda: self._stop)
            self.finished_analysis.emit(count, '')
        except Exception as exc:
            logger.error("Analysis failed: %s", exc)
            self.finished_analysis.emit(0, str(exc))
        finally:
            if case is not None:
                try:
                    case.close()
                except Exception:
                    pass
            if handler is not None:
                try:
                    handler.close_resources()
                except Exception:
                    pass


class TriagePanel(QWidget):
    """The findings, grouped by the reason they are findings."""

    #: Emitted with a row when the examiner opens one, so the host can jump to
    #: it the same way it jumps to a bookmark or a search result.
    finding_activated = Signal(dict)

    #: Emitted with (row, global position) on a right-click, so the host can
    #: offer the same context menu it offers everywhere else.
    finding_menu_requested = Signal(dict, object)

    #: Emitted when the examiner asks for a run from here.
    run_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("triagePanel")
        self.case = None
        self.evidence_id = None
        self.icon_resolver = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(4)

        header = QHBoxLayout()
        header.setSpacing(6)
        self.status_label = QLabel()
        self.status_label.setObjectName("triageStatus")
        self.status_label.setWordWrap(False)
        header.addWidget(self.status_label, 1)

        self.run_button = QPushButton("Run Analysis")
        self.run_button.setObjectName("triageRunButton")
        self.run_button.setFixedHeight(CONTROL_HEIGHT)
        self.run_button.clicked.connect(self.run_requested.emit)
        header.addWidget(self.run_button)
        layout.addLayout(header)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("triageTabs")
        self.tabs.setDocumentMode(True)
        layout.addWidget(self.tabs, 1)

        self.mismatch_table = self._make_table(
            ['Name', 'Claims to be', 'Actually is', 'Why', 'Size', 'Path'])
        self.tabs.addTab(self.mismatch_table, "Type mismatches")

        self.entropy_table = self._make_table(
            ['Name', 'Entropy', 'Peak', 'Type', 'Size', 'Path'])
        self.tabs.addTab(self.entropy_table, "High entropy")

        self.duplicate_table = self._make_table(
            ['Name', 'Copies', 'Size', 'Wasted', 'SHA-256', 'Path'])
        self.tabs.addTab(self.duplicate_table, "Duplicates")

        self.refresh()

    def _make_table(self, headers):
        table = QTableWidget()
        table.setObjectName("triageTable")
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        table.itemDoubleClicked.connect(self._activate)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(
            lambda point, t=table: self._context_menu(t, point))
        return table

    def set_case(self, case, evidence_id=None):
        self.case = case
        self.evidence_id = evidence_id
        self.refresh()

    def refresh(self):
        """Redraw from what the case holds now."""
        if self.case is None:
            self.status_label.setText(
                "Analysis findings are kept in a case. File ▸ New Case "
                "starts one.")
            self.run_button.setEnabled(False)
            for table in (self.mismatch_table, self.entropy_table,
                          self.duplicate_table):
                table.setRowCount(0)
            self._set_counts(0, 0, 0)
            return

        self.run_button.setEnabled(True)
        summary = self.case.analysis_summary(self.evidence_id)

        if not summary['analysed']:
            state = (self.case.analysis_state(self.evidence_id)
                     if self.evidence_id else None)
            if state and state['status'] == 'running':
                self.status_label.setText("Analysis is running…")
            else:
                self.status_label.setText(
                    "Nothing analysed yet. Run Analysis examines every file "
                    "for its true type, entropy and hash.")
        else:
            self.status_label.setText(
                f"{summary['analysed']:,} file(s) analysed")

        self._fill_mismatches()
        self._fill_entropy()
        self._fill_duplicates()
        self._set_counts(summary['mismatches'], summary['high_entropy'],
                         summary['duplicate_groups'])

    def _set_counts(self, mismatches, entropy, duplicates):
        # The count belongs on the tab, so it is readable whichever tab is
        # open -- an examiner should be able to see there are findings without
        # clicking through all three.
        self.tabs.setTabText(0, f"Type mismatches ({mismatches})")
        self.tabs.setTabText(1, f"High entropy ({entropy})")
        self.tabs.setTabText(2, f"Duplicates ({duplicates})")

    def _icon_for(self, name):
        if not self.icon_resolver:
            return None
        extension = name.rsplit('.', 1)[-1].lower() if '.' in name else 'unknown'
        return self.icon_resolver(extension)

    def _fill_mismatches(self):
        rows = self.case.type_mismatches(self.evidence_id,
                                         grade=REPORTED_MISMATCHES)
        # Suspicious first: an executable wearing a document's extension is a
        # different order of finding from an encrypted document, and sorting
        # by name would bury it.
        rows.sort(key=lambda r: (r.get('mismatch') != 'suspicious',
                                 r.get('name') or ''))
        table = self.mismatch_table
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            values = [
                row.get('name') or '',
                f".{row.get('extension') or ''}",
                row.get('mime') or '',
                _WHY.get(row.get('mismatch'), ''),
                FileSystemUtils.get_readable_size(row.get('size') or 0),
                row.get('path') or '',
            ]
            self._fill_row(table, position, values, row)

    def _fill_entropy(self):
        rows = self.case.high_entropy_files(self.evidence_id)
        table = self.entropy_table
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            values = [
                row.get('name') or '',
                f"{row.get('entropy') or 0:.2f}",
                f"{row.get('entropy_peak') or 0:.2f}",
                row.get('mime') or '',
                FileSystemUtils.get_readable_size(row.get('size') or 0),
                row.get('path') or '',
            ]
            self._fill_row(table, position, values, row)

    def _fill_duplicates(self):
        groups = self.case.duplicate_groups(self.evidence_id)
        table = self.duplicate_table
        # One row per copy, with the group's hash repeated: an examiner needs
        # to see where each copy lives, which a collapsed group row hides.
        rows = [(group, member) for group in groups
                for member in group['members']]
        table.setRowCount(len(rows))
        for position, (group, member) in enumerate(rows):
            size = member.get('size') or 0
            values = [
                member.get('name') or '',
                str(group['copies']),
                FileSystemUtils.get_readable_size(size),
                FileSystemUtils.get_readable_size(
                    size * (group['copies'] - 1)),
                (group['sha256'] or '')[:16] + '…',
                member.get('path') or '',
            ]
            self._fill_row(table, position, values, member)

    def _fill_row(self, table, position, values, payload):
        for column, value in enumerate(values):
            cell = QTableWidgetItem(str(value))
            if column == 0:
                cell.setData(Qt.UserRole, payload)
                icon = self._icon_for(payload.get('name') or '')
                if icon is not None:
                    cell.setIcon(icon)
                cell.setToolTip(payload.get('path') or '')
            table.setItem(position, column, cell)
        if position == table.rowCount() - 1:
            fit_columns(table, {table.columnCount() - 1: 260})

    def _activate(self, item):
        row = item.tableWidget().item(item.row(), 0).data(Qt.UserRole)
        if row:
            self.finding_activated.emit(row)

    def _context_menu(self, table, point):
        item = table.itemAt(point)
        if item is None:
            return
        row = table.item(item.row(), 0).data(Qt.UserRole)
        if row:
            self.finding_menu_requested.emit(
                row, table.viewport().mapToGlobal(point))
