"""Keywords: what the case's keyword lists found (core/keywords.py).

A Triage sub-tab, laid out like Indicators: the terms above -- by list,
the most widespread first, with how many files hold each and how often --
and below them the files holding the one selected, each with the first hit
in context. Landing on a file previews it; double-click goes to its folder.
"""

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView,
                               QLabel, QPushButton, QSizePolicy, QSplitter,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from trace_app.core import keywords
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.row_preview import connect_row_preview

logger = logging.getLogger('TRACE.KeywordsPanel')

_TONE = {'suspicious': 'malicious', 'notable': 'suspicious'}


class _Number(QTableWidgetItem):
    """Sorts by the number, not the text."""

    def __lt__(self, other):
        return (self.data(Qt.UserRole + 1) or 0) < \
            (other.data(Qt.UserRole + 1) or 0)


class KeywordsPanel(QWidget):
    file_selected = Signal(dict)
    file_activated = Signal(dict)
    file_menu_requested = Signal(dict, object)
    #: Terms with hits, for the sub-tab's label.
    count_changed = Signal(int)
    manage_requested = Signal()
    search_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("keywordsPanel")
        self.case = None
        self.evidence_id = None
        self._names = {}
        self._findings = []
        self._terms = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)
        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.status_label = QLabel()
        self.status_label.setObjectName("indicatorStatus")
        self.status_label.setSizePolicy(QSizePolicy.Ignored,
                                        QSizePolicy.Preferred)
        bar.addWidget(self.status_label, 1)
        self.manage_button = QPushButton("Keyword Lists…")
        self.manage_button.clicked.connect(self.manage_requested.emit)
        bar.addWidget(self.manage_button)
        self.search_button = QPushButton("Search Now")
        self.search_button.setToolTip("Search the case's index with the "
                                      "lists it uses")
        self.search_button.clicked.connect(self.search_requested.emit)
        bar.addWidget(self.search_button)
        layout.addLayout(bar)

        splitter = QSplitter(Qt.Vertical)
        splitter.setObjectName("indicatorSplitter")
        layout.addWidget(splitter, 1)
        self.terms_table = self._table(['Term', 'List', 'Type', 'Files',
                                        'Hits', 'Note'])
        self.terms_table.setSortingEnabled(True)
        self.terms_table.itemSelectionChanged.connect(self._fill_files)
        splitter.addWidget(self.terms_table)
        self.files_table = self._table(['Name', 'Evidence', 'Hits',
                                        'Context', 'Size', 'Path'])
        connect_row_preview(self.files_table, self.file_selected.emit)
        self.files_table.itemDoubleClicked.connect(
            lambda item: self.file_activated.emit(
                self.files_table.item(item.row(), 0).data(Qt.UserRole)))
        self.files_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.files_table.customContextMenuRequested.connect(self._files_menu)
        splitter.addWidget(self.files_table)
        splitter.setSizes([260, 240])
        self.refresh()

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

    # --- what to show ----------------------------------------------------

    def set_case(self, case):
        self.case = case
        self._names = {r['id']: r.get('display_name')
                       or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                       for r in case.evidence()} if case else {}
        self.search_button.setEnabled(case is not None)
        self.refresh()

    def set_evidence_filter(self, evidence_id):
        if evidence_id == self.evidence_id:
            return
        self.evidence_id = evidence_id
        self.refresh()

    def shutdown(self):
        pass

    def refresh(self, select=None):
        self._findings = self.case.findings(
            self.evidence_id, keywords.MODULE_KEYWORDS, limit=500000) \
            if self.case is not None else []
        self._terms = keywords.term_summary(self._findings)
        table = self.terms_table
        table.setSortingEnabled(False)
        table.setRowCount(len(self._terms))
        for row, term in enumerate(self._terms):
            cells = [QTableWidgetItem(term['term'] or ''),
                     QTableWidgetItem(term['list'] or ''),
                     QTableWidgetItem(keywords.KIND_LABELS.get(
                         term['term_kind'], term['term_kind'] or '')),
                     _Number(f"{term['files']:,}"
                             + ('+' if term['truncated'] else '')),
                     _Number(f"{term['hits']:,}"),
                     QTableWidgetItem(term['note'])]
            cells[3].setData(Qt.UserRole + 1, term['files'])
            cells[4].setData(Qt.UserRole + 1, term['hits'])
            cells[0].setData(Qt.UserRole, (term['list_id'], term['term']))
            tone = _TONE.get(term['grade'])
            if tone:
                cells[0].setForeground(verdict_brush(tone))
            cells[0].setToolTip(f"{term['grade'] or ''} — "
                                f"{term['list'] or ''}")
            for column, cell in enumerate(cells):
                table.setItem(row, column, cell)
        table.setSortingEnabled(True)
        for column, width in enumerate((220, 160, 130, 70, 70)):
            table.setColumnWidth(column, width)
        if self.case is None:
            text = "Keyword searches are kept in a case."
        elif not self._terms:
            text = ("No keyword hits. Keyword Lists… keeps your terms; "
                    "Search Now runs them over the case's search index.")
        else:
            files = len({(f['evidence_id'], f['artifact_ref'], f['path'])
                         for f in self._findings})
            text = (f"{len(self._terms):,} term(s) found in {files:,} "
                    f"file(s)")
        self.status_label.setText(text)
        self.status_label.setToolTip(text)
        self.count_changed.emit(len(self._terms))
        if self._terms:
            self.select_term(*(select or (None, None)))
        else:
            self.files_table.setRowCount(0)

    def select_term(self, list_id=None, term=None):
        """Select a term (the first when not given)."""
        table = self.terms_table
        for row in range(table.rowCount()):
            key = table.item(row, 0).data(Qt.UserRole)
            if term is None or key == (list_id, term) or (
                    list_id is None and key[1] == term):
                table.selectRow(row)
                return

    def _fill_files(self):
        row = self.terms_table.currentRow()
        if row < 0:
            self.files_table.setRowCount(0)
            return
        key = self.terms_table.item(row, 0).data(Qt.UserRole)
        rows = [f for f in self._findings
                if ((f.get('detail') or {}).get('list_id'),
                    (f.get('detail') or {}).get('term')) == tuple(key)]
        rows.sort(key=lambda f: -int((f.get('detail') or {}).get('hits')
                                     or 0))
        table = self.files_table
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for position, finding in enumerate(rows):
            detail = finding.get('detail') or {}
            hits = int(detail.get('hits') or 0)
            cells = [QTableWidgetItem(finding.get('name') or ''),
                     QTableWidgetItem(self._names.get(
                         finding.get('evidence_id'), '')),
                     _Number(f"{hits:,}" + ('+' if hits >=
                                            keywords.MAX_COUNT else '')),
                     QTableWidgetItem(detail.get('excerpt') or ''),
                     _Number(FileSystemUtils.get_readable_size(
                         finding.get('size') or 0)),
                     QTableWidgetItem(finding.get('path') or '')]
            cells[2].setData(Qt.UserRole + 1, hits)
            cells[4].setData(Qt.UserRole + 1, finding.get('size') or 0)
            cells[3].setToolTip(detail.get('excerpt') or '')
            cells[5].setToolTip(finding.get('path') or '')
            cells[0].setData(Qt.UserRole, finding)
            for column, cell in enumerate(cells):
                table.setItem(position, column, cell)
        table.setSortingEnabled(True)
        for column, width in enumerate((200, 120, 60, 380, 80)):
            table.setColumnWidth(column, width)

    def _files_menu(self, point):
        item = self.files_table.itemAt(point)
        if item is None:
            return
        finding = self.files_table.item(item.row(), 0).data(Qt.UserRole)
        self.file_menu_requested.emit(
            finding, self.files_table.viewport().mapToGlobal(point))
