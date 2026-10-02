"""Indicators: every email, URL, number and address the evidence holds.

A Triage sub-tab. The values come from the case's search index -- indexing
extracts them (core/search_index.py), and indexing is an analysis module run
from Analysis > Run Analysis Modules. This tab only reads.

Two lists, one above the other: the distinct values, most widespread first,
and below them the files holding the one selected. Landing on a file previews
it and leaves the lists where they are; double-click goes to its folder --
the same way every other Triage list is worked down.
"""

import logging

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QMenu,
                               QSplitter, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from trace_app.core.search_index import INDICATOR_KINDS, SearchIndex
from trace_app.infra.constants import CONTROL_HEIGHT, TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.row_preview import connect_row_preview
from trace_app.ui.widgets.table_columns import fit_columns

logger = logging.getLogger('TRACE.Indicators')


def kind_label(kind, plural=False):
    names = INDICATOR_KINDS.get(kind)
    return names[1 if plural else 0] if names else kind


class IndicatorsPanel(QWidget):
    """The case's indicators, and the files each one was found in."""

    #: A file holding the selected value, landed on: preview it.
    file_selected = Signal(dict)
    #: Double-clicked: go to its folder.
    file_activated = Signal(dict)
    #: Right-clicked: (row, global position), for the host's file menu.
    file_menu_requested = Signal(dict, object)
    #: "Search for this": a query for the Search tab.
    search_requested = Signal(str)
    #: Distinct values shown, for the sub-tab's label.
    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("indicatorsPanel")
        self.case = None
        self.index = None
        self.evidence_id = None
        self.kind = None
        self.count = 0
        self._names = {}
        self.icon_resolver = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)

        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.kind_combo = QComboBox()
        self.kind_combo.setObjectName("indicatorKindCombo")
        self.kind_combo.setFixedHeight(CONTROL_HEIGHT)
        self.kind_combo.currentIndexChanged.connect(self._kind_changed)
        bar.addWidget(self.kind_combo)

        self.filter_input = QLineEdit()
        self.filter_input.setObjectName("indicatorFilter")
        self.filter_input.setPlaceholderText("Filter values…")
        self.filter_input.setClearButtonEnabled(True)
        # Typing narrows as it goes, without a query per keystroke.
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(250)
        self._filter_timer.timeout.connect(self._fill_values)
        self.filter_input.textChanged.connect(
            lambda _text: self._filter_timer.start())
        bar.addWidget(self.filter_input, 1)

        self.status_label = QLabel()
        self.status_label.setObjectName("indicatorStatus")
        bar.addWidget(self.status_label)
        layout.addLayout(bar)

        splitter = QSplitter(Qt.Vertical)
        splitter.setObjectName("indicatorSplitter")
        layout.addWidget(splitter, 1)

        self.values_table = self._table(['Value', 'Kind', 'Files', 'Evidence'])
        self.values_table.itemSelectionChanged.connect(self._fill_files)
        self.values_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.values_table.customContextMenuRequested.connect(
            self._values_menu)
        splitter.addWidget(self.values_table)

        self.files_table = self._table(['Name', 'Evidence', 'Context', 'Size',
                                        'Modified', 'Path'])
        connect_row_preview(self.files_table, self.file_selected.emit)
        self.files_table.itemDoubleClicked.connect(self._activate_file)
        self.files_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.files_table.customContextMenuRequested.connect(self._files_menu)
        splitter.addWidget(self.files_table)
        splitter.setSizes([300, 200])

        self._fill_kinds({})

    @staticmethod
    def _table(headers):
        table = QTableWidget()
        table.setObjectName("triageTable")
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setItemDelegate(NoFocusDelegate(table))
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    # --- what to show -----------------------------------------------------

    def set_case(self, case):
        """Show `case`'s indicators. Reopens the index, so values written by
        an indexing job through its own connection are seen."""
        if self.index is not None:
            self.index.close()
            self.index = None
        self.case = case
        self._names = {}
        if case is not None:
            self._names = {r['id']: r.get('display_name')
                           or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                           for r in case.evidence()}
            try:
                self.index = SearchIndex(case.folder)
            except Exception as exc:
                logger.error("Could not open the search index: %s", exc)
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        """Follow Triage's image filter: one image, or None for all."""
        if evidence_id == self.evidence_id:
            return
        self.evidence_id = evidence_id
        self.refresh()

    def set_kind(self, kind):
        """Show one kind ('email', 'url'...), or None for every kind."""
        position = self.kind_combo.findData(kind)
        self.kind_combo.setCurrentIndex(position if position >= 0 else 0)

    def summary(self):
        """{kind: distinct values} for the current image filter."""
        if self.index is None:
            return {}
        try:
            return self.index.indicator_summary(self.evidence_id)
        except Exception as exc:
            logger.error("Could not read indicators: %s", exc)
            return {}

    def refresh(self):
        self._fill_kinds(self.summary())
        self._fill_values()

    def _fill_kinds(self, counts):
        """The kind filter, each with its count; kinds with none are left
        out, so the list says what was found."""
        keep = self.kind
        self.kind_combo.blockSignals(True)
        self.kind_combo.clear()
        self.kind_combo.addItem(
            f"All indicators ({sum(counts.values()):,})", None)
        for kind in INDICATOR_KINDS:
            if counts.get(kind):
                self.kind_combo.addItem(
                    f"{kind_label(kind, True)} ({counts[kind]:,})", kind)
        position = self.kind_combo.findData(keep)
        self.kind_combo.setCurrentIndex(position if position >= 0 else 0)
        self.kind_combo.blockSignals(False)
        self.kind = self.kind_combo.currentData()

    def _kind_changed(self, _position):
        self.kind = self.kind_combo.currentData()
        self._fill_values()

    def _fill_values(self):
        table = self.values_table
        table.setSortingEnabled(False)
        table.setRowCount(0)
        self.files_table.setRowCount(0)
        rows = []
        if self.index is not None:
            try:
                rows = self.index.indicators(
                    self.kind, self.evidence_id,
                    self.filter_input.text().strip())
            except Exception as exc:
                logger.error("Could not list indicators: %s", exc)
        self._set_status(rows)
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            images = ', '.join(self._names.get(e, f'#{e}')
                               for e in row['evidence_ids'])
            cells = [QTableWidgetItem(row['value']),
                     QTableWidgetItem(kind_label(row['kind'])),
                     _NumberItem(row['files']),
                     QTableWidgetItem(images)]
            cells[0].setData(Qt.UserRole, row)
            cells[0].setToolTip(row['value'])
            cells[3].setToolTip(images)
            for column, cell in enumerate(cells):
                table.setItem(position, column, cell)
        table.setSortingEnabled(True)
        if rows:
            fit_columns(table, {0: 520, 3: 260})
        # The tab counts every distinct value for the image filter, not what
        # the kind or text filter happens to leave showing.
        self.count = sum(self.summary().values())
        self.count_changed.emit(self.count)

    def _set_status(self, rows):
        if self.case is None:
            text = "Indicators are kept with a case."
        elif self.index is None or not self.index.statistics(
                self.evidence_id)['items']:
            text = ("Nothing indexed yet: run Search index and indicators "
                    "from Analysis ▸ Run Analysis Modules.")
        elif not rows:
            text = "No indicators match."
        else:
            text = f"{len(rows):,} value(s)"
        self.status_label.setText(text)

    def selected_value(self):
        items = self.values_table.selectedItems()
        if not items:
            return None
        return self.values_table.item(items[0].row(), 0).data(Qt.UserRole)

    def _fill_files(self):
        table = self.files_table
        table.setRowCount(0)
        value = self.selected_value()
        if value is None or self.index is None:
            return
        try:
            rows = self.index.items_with(value['kind'], value['value'],
                                         self.evidence_id)
        except Exception as exc:
            logger.error("Could not list files for %s: %s",
                         value['value'], exc)
            return
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            row['evidence_name'] = self._names.get(row.get('evidence_id'), '')
            excerpt = (row.get('excerpt') or '').strip()
            size = row.get('size') or 0
            cells = [QTableWidgetItem(row.get('name') or ''),
                     QTableWidgetItem(row['evidence_name']),
                     QTableWidgetItem(excerpt),
                     _NumberItem(size,
                                 FileSystemUtils.get_readable_size(size)
                                 if size else ''),
                     QTableWidgetItem(row.get('mtime_utc') or ''),
                     QTableWidgetItem(row.get('path') or '')]
            cells[0].setData(Qt.UserRole, row)
            cells[0].setToolTip(row.get('path') or '')
            cells[2].setToolTip(excerpt)
            cells[5].setToolTip(row.get('path') or '')
            if self.icon_resolver:
                name = row.get('name') or ''
                extension = (name.rsplit('.', 1)[-1].lower()
                             if '.' in name else 'unknown')
                icon = self.icon_resolver(extension)
                if icon is not None:
                    cells[0].setIcon(icon)
            for column, cell in enumerate(cells):
                table.setItem(position, column, cell)
        fit_columns(table, {2: 420, 5: 300})
        table.setColumnWidth(0, max(table.columnWidth(0), 160))

    # --- actions ------------------------------------------------------------

    def _values_menu(self, point):
        item = self.values_table.itemAt(point)
        if item is None:
            return
        row = self.values_table.item(item.row(), 0).data(Qt.UserRole)
        menu = QMenu(self)
        copy = menu.addAction("Copy Value")
        search = menu.addAction("Search for This Value")
        chosen = menu.exec_(self.values_table.viewport().mapToGlobal(point))
        if chosen == copy:
            QGuiApplication.clipboard().setText(row['value'])
        elif chosen == search:
            self.search_requested.emit(f"{row['kind']}:{row['value']}")

    def _files_menu(self, point):
        item = self.files_table.itemAt(point)
        if item is None:
            return
        row = self.files_table.item(item.row(), 0).data(Qt.UserRole)
        if row:
            self.file_menu_requested.emit(
                row, self.files_table.viewport().mapToGlobal(point))

    def _activate_file(self, item):
        row = self.files_table.item(item.row(), 0).data(Qt.UserRole)
        if row:
            self.file_activated.emit(row)

    def shutdown(self):
        if self.index is not None:
            self.index.close()
            self.index = None


class _NumberItem(QTableWidgetItem):
    """A cell that sorts by its number, whatever it displays."""

    def __init__(self, number, text=None):
        super().__init__(f"{number:,}" if text is None else text)
        self._number = number

    def __lt__(self, other):
        if isinstance(other, _NumberItem):
            return self._number < other._number
        return super().__lt__(other)
