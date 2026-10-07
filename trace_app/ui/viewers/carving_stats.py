"""The Statistics view of Carved files: what each carve run saw and kept,
from its row in carving_runs (Case.carving_runs).

For a run: where it looked and how much it read; every signature hit
checked by a validator and how many were rejected as not the format --
the carver's false-positive rate, measured -- what was kept, by status
(complete / valid / reconstructed / partial), how many were named from a
deleted entry, identical copies and WAL files paired with a database. Then
the same per type. Nothing is computed here that the run did not record.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout,
                               QHeaderView, QLabel, QSplitter, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from trace_app.core.carve_verify import STATUSES, STATUS_LABELS
from trace_app.core.carving import SOURCE_LABELS
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.property_table import PropertyTable

#: Width of the text bar showing what share of a type's hits were kept.
BAR_WIDTH = 20

_TYPE_COLUMNS = ('Type', 'Checked', 'Rejected', 'Kept', 'Kept of checked')


class _Number(QTableWidgetItem):
    """Sorts by its number, not its text."""

    def __init__(self, value, text=None):
        super().__init__(text if text is not None else f"{value:,}")
        self.setData(Qt.UserRole, value)
        self.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

    def __lt__(self, other):
        return (self.data(Qt.UserRole) or 0) < (other.data(Qt.UserRole) or 0)


def bar(share):
    """'██████░░░░  60%' -- a share drawn in text, theme-neutral."""
    filled = round(share * BAR_WIDTH)
    return '█' * filled + '░' * (BAR_WIDTH - filled) + f" {share:4.0%}"


def run_rows(run, evidence_name=''):
    """(field, value) rows of one run's summary."""
    stats = run.get('stats') or {}
    settings = run.get('settings') or {}
    candidates = sum((stats.get('candidates') or {}).values())
    rejected = sum((stats.get('rejected') or {}).values())
    kept = run.get('found')
    if kept is None:
        kept = sum((stats.get('kept') or {}).values())
    rows = [(None, f"Run {run.get('id')} — {evidence_name}"),
            ("Status", (run.get('status') or '').capitalize()),
            ("Started", f"{run.get('started_utc') or ''} UTC"),
            ("Finished", f"{run.get('finished_utc')} UTC"
             if run.get('finished_utc') else "not finished"),
            ("Source", SOURCE_LABELS.get(settings.get('source'),
                                         settings.get('source') or '')),
            ("Types asked for", ', '.join(settings.get('types') or [])),
            ("Engine", run.get('engine') or ''),
            ("Bytes read", f"{stats.get('bytes_scanned', 0):,}"),
            ("Bytes skipped (allocated)",
             f"{stats.get('bytes_skipped', 0):,}"),
            (None, "Candidates"),
            ("Signature hits checked", f"{candidates:,}"),
            ("Rejected as not the format",
             f"{rejected:,}" + (f" ({rejected / candidates:.0%})"
                                if candidates else '')),
            ("Kept", f"{kept:,}")]
    statuses = stats.get('status') or {}
    if statuses:
        rows.append((None, "Kept, by what their structure proved"))
        for status in STATUSES:
            if statuses.get(status):
                rows.append((STATUS_LABELS.get(status, status),
                             f"{statuses[status]:,}"))
    rows += [(None, "Related"),
             ("Named from deleted entries", f"{stats.get('named', 0):,}"),
             ("Identical copies", f"{stats.get('duplicates', 0):,}"),
             ("WAL files paired with a database",
              f"{stats.get('wal_pairs', 0):,}")]
    if settings.get('resumed_from'):
        rows.append(("Resumed from byte", f"{settings['resumed_from']:,}"))
    return rows


def type_rows(run):
    """[(type, checked, rejected, kept)] of one run, most hits first."""
    stats = run.get('stats') or {}
    candidates = stats.get('candidates') or {}
    rejected = stats.get('rejected') or {}
    kept = stats.get('kept') or {}
    kinds = set(candidates) | set(kept)
    out = [(kind, candidates.get(kind, 0), rejected.get(kind, 0),
            kept.get(kind, 0)) for kind in kinds]
    return sorted(out, key=lambda r: (-r[1], -r[3], r[0]))


class CarvingStatsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("carvingStats")
        self._runs, self._names = [], {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)
        bar_row = QHBoxLayout()
        bar_row.addWidget(QLabel("Run"))
        self.run_combo = QComboBox()
        self.run_combo.setObjectName("carvingRunCombo")
        self.run_combo.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.run_combo.currentIndexChanged.connect(self._show_run)
        bar_row.addWidget(self.run_combo)
        self.note = QLabel()
        self.note.setObjectName("indicatorStatus")
        bar_row.addWidget(self.note, 1)
        layout.addLayout(bar_row)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("indicatorSplitter")
        layout.addWidget(splitter, 1)
        self.summary = PropertyTable("Field", "Value")
        splitter.addWidget(self.summary)
        self.types = QTableWidget()
        self.types.setObjectName("triageTable")
        self.types.setColumnCount(len(_TYPE_COLUMNS))
        self.types.setHorizontalHeaderLabels(_TYPE_COLUMNS)
        self.types.verticalHeader().setVisible(False)
        self.types.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.types.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.types.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.types.setItemDelegate(NoFocusDelegate(self.types))
        self.types.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        self.types.horizontalHeader().setStretchLastSection(True)
        self.types.setSortingEnabled(True)
        splitter.addWidget(self.types)
        splitter.setSizes([380, 520])

    def set_runs(self, runs, names):
        """Every run to choose from, newest first; {evidence id: name}."""
        current = self.run_combo.currentData()
        self._runs, self._names = list(runs), dict(names)
        self.run_combo.blockSignals(True)
        self.run_combo.clear()
        for run in self._runs:
            self.run_combo.addItem(
                f"{self._names.get(run['evidence_id'], '')} · run "
                f"{run['id']} · {run.get('status') or ''} · "
                f"{(run.get('started_utc') or '')[:16]}", run['id'])
        index = self.run_combo.findData(current)
        self.run_combo.setCurrentIndex(index if index >= 0 else 0)
        self.run_combo.blockSignals(False)
        self.run_combo.setVisible(bool(self._runs))
        self._show_run()

    def _show_run(self, _index=None):
        run = next((r for r in self._runs
                    if r['id'] == self.run_combo.currentData()), None)
        if run is None:
            self.note.setText("No carve has run on this evidence yet.")
            self.summary.set_rows([])
            self.types.setRowCount(0)
            return
        self.note.setText(
            "What the run recorded. Checked: signature hits a validator "
            "parsed; rejected: hits that were not the format; kept: files "
            "written (inside another carve and repeats are not kept).")
        self.summary.set_rows(run_rows(run,
                                       self._names.get(run['evidence_id'],
                                                       '')))
        rows = type_rows(run)
        table = self.types
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for position, (kind, checked, rejected, kept) in enumerate(rows):
            share = kept / checked if checked else (1.0 if kept else 0.0)
            cells = [QTableWidgetItem(kind.upper()), _Number(checked),
                     _Number(rejected), _Number(kept),
                     _Number(share, bar(min(share, 1.0)))]
            for column, cell in enumerate(cells):
                table.setItem(position, column, cell)
        table.setSortingEnabled(True)
        for column, width in enumerate((90, 90, 90, 80)):
            table.setColumnWidth(column, width)
