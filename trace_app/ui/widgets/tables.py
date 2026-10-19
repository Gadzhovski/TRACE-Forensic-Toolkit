"""The finding tables of Triage's tabs, Indicators, Keywords and the Map:
one shape, built in one place."""

from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget

from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate


def finding_table(headers, selection=QAbstractItemView.SingleSelection):
    """A read-only, row-selecting table styled as a triage table. Its
    delegate paints cells' own colours (severity, verdicts), which the
    themes' item colour would otherwise override."""
    table = QTableWidget()
    table.setObjectName("triageTable")
    table.setColumnCount(len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(selection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setItemDelegate(NoFocusDelegate(table))
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    table.horizontalHeader().setStretchLastSection(True)
    return table
