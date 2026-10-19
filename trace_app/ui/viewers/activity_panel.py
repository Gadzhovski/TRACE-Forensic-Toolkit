"""Activity: what the people using each device did.

A top-level tab beside Triage. Sub-tabs follow core/activity's categories --
programs run, files and folders, USB devices, the Recycle Bin, logons and
remote access, web history, downloads and searches -- with "All" first, every
record in time order: the beginnings of a timeline. Every row names the file
it was read from; landing on it previews that file, double-click goes to it.

A model-based view: a busy machine's browser history alone is tens of
thousands of rows, and building a QTableWidgetItem per cell for that is
seconds of frozen window. Rows are read on a thread of their own, from a
read-only connection to the case database.
"""

import json
import logging
import sqlite3

from PySide6.QtCore import (QAbstractTableModel, QModelIndex,
                            QSortFilterProxyModel, Qt, QTimer, Signal)
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout,
                               QHeaderView, QLineEdit, QMenu, QPushButton,
                               QSizePolicy, QStackedWidget, QTableView,
                               QToolBar, QToolButton, QVBoxLayout, QWidget)

from trace_app.core import record_views
from trace_app.core.activity import CATEGORIES
from trace_app.core.case import query_user_activity
from trace_app.infra import config_store
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui import icons
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.widgets.elided_label import ElidedLabel
from trace_app.ui.widgets.kept_threads import KeptThreads
from trace_app.ui.widgets.case_query import CaseQuery
from trace_app.ui.widgets.section_nav import GroupedTabs
from trace_app.ui.widgets.toolbars import prepare_toolbar
from trace_app.ui.viewers.module_records import (ModuleRecordsView,
                                               count_hidden,
                                               hidden_artifacts)
from trace_app.ui.viewers.record_views import ItemsView, RecordOverview
from trace_app.ui.widgets.context_menus import show_menu

logger = logging.getLogger('TRACE.ActivityPanel')

#: Most rows read at once; the text filter and the categories narrow it.
SHOWN_LIMIT = 50000
#: Rows whose Charts or Items are worked out at once; more go to a child
#: process (core/background.job_record_view): 38,000 rows took 0.4 s.
INLINE_ROWS = 5000

#: The tab rows: groups on top, their categories under them
#: (ui/widgets/section_nav.GroupedTabs). Fourteen categories in one row ran
#: past the window's edge.
GROUPS = (('all', "All"),
          ('programs', "Programs & system"),
          ('files', "Files & devices"),
          ('web', "Web"),
          ('accounts', "Accounts & network"),
          ('communication', "Communication"),
          # What external modules read that TRACE did not sort as evidence;
          # shown only when there is some (module_records.py).
          ('modules', "Others"))

#: The Others group's tabs: (roles, label, icon).
MODULE_TABS = ((('other',), "Other records", icons.MODULES),
               (('telemetry',), "Telemetry", icons.TIMELINE))

#: The group each category's tab is under (None: All).
GROUP_OF = {None: 'all',
            'programs': 'programs', 'system': 'programs',
            'usage': 'programs', 'antivirus': 'programs',
            'files': 'files', 'usb': 'files', 'recycle': 'files',
            'notes': 'files',
            'browser': 'web', 'downloads': 'web', 'searches': 'web',
            'logons': 'accounts', 'network': 'accounts', 'cloud': 'accounts',
            'accounts': 'accounts', 'calendar': 'files', 'records': 'files',
            'communication': 'communication', 'locations': 'communication'}

#: A column: (title, what it shows, width). 'd:<key>' is a detail value
#: under the key TRACE's readers and the LEAPPs' maps both use
#: (core/modules/record_types.DETAIL_KEYS); 'd:a|b' the first present.
_C = {
    'time': ('Time', 'time', 150), 'what': ('What', 'what', 170),
    'subject': ('Subject', 'subject', 380), 'user': ('User', 'user', 110),
    'details': ('Details', 'details', 320),
    'source': ('Source', 'source', 140),
    'read_by': ('Read by', 'read_by', 110),
    'evidence': ('Evidence', 'evidence', 140),
    'file': ('Source file', 'file', 260),
    'party': ('Party', 'party', 160), 'name': ('Name', 'd:name', 140),
    'text': ('Text', 'subject', 380),
    'duration': ('Duration', 'd:duration', 80),
    'app': ('App', 'app', 130),
    'url': ('URL', 'd:url|subject', 360), 'title': ('Title', 'd:title', 240),
    'visits': ('Visits', 'd:visits|visit count', 70),
    'browser': ('Browser', 'd:browser|source', 130),
    'place': ('Place', 'subject', 300),
    'latitude': ('Latitude', 'd:latitude', 100),
    'longitude': ('Longitude', 'd:longitude', 100),
    'accuracy': ('Accuracy', 'd:accuracy', 80),
    'account': ('Account', 'd:account|subject', 240),
    'service': ('Service', 'd:service', 140),
    'network': ('Network', 'd:ssid|SSID|subject', 220),
    'bssid': ('BSSID', 'd:BSSID|bssid|mac address', 140),
    'security': ('Security', 'd:security|authentication', 120),
    'version': ('Version', 'd:version', 110),
}
_TAIL = ('read_by', 'evidence', 'file', 'details')
#: Each category's columns, typed where the records are ('All' and the
#: rest: the generic ones). TRACE's rows and the LEAPPs' fill the same.
LAYOUTS = {
    None: ('time', 'what', 'subject', 'user', 'details', 'source',
           'read_by', 'evidence', 'file'),
    'communication': ('time', 'what', 'party', 'name', 'text', 'duration',
                      'app') + _TAIL,
    'browser': ('time', 'what', 'url', 'title', 'visits', 'browser',
                'user') + _TAIL,
    'downloads': ('time', 'what', 'url', 'browser', 'user') + _TAIL,
    'searches': ('time', 'what', 'subject', 'browser', 'user') + _TAIL,
    'locations': ('time', 'what', 'place', 'latitude', 'longitude',
                  'accuracy', 'source') + _TAIL,
    'accounts': ('time', 'what', 'account', 'service', 'app',
                 'user') + _TAIL,
    'network': ('time', 'what', 'network', 'bssid', 'security',
                'source') + _TAIL,
    'system': ('time', 'what', 'subject', 'version', 'user',
               'source') + _TAIL,
    'programs': ('time', 'what', 'subject', 'version', 'user',
                 'source') + _TAIL,
}
#: Sorted as numbers, not text.
_NUMERIC = {'visits', 'latitude', 'longitude', 'accuracy', 'duration'}
SORT_ROLE = Qt.UserRole + 1
# The 'All' layout's columns, for callers and tests.
READ_BY, EVIDENCE = 6, 7


def _seconds(text):
    """'1:05' / '1:02:03' / '65' -> seconds, else None."""
    try:
        parts = [float(p) for p in str(text).split(':')]
    except ValueError:
        return None
    total = 0.0
    for part in parts:
        total = total * 60 + part
    return total


class ActivityWorker(ProcessWorker):
    """Reads one image's activity in a child process (core/background.py)."""

    progressed = Signal(object, object, str)
    finished_activity = Signal(int, str)

    kind = 'activity'

    def __init__(self, image_path, case_folder, evidence_id, parent=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id}, parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_activity.emit(count, error)


def detail_text(detail, limit=None, shown=()):
    """'key: value; key: value' -- one line for the table, leaving out
    the keys a column of their own already shows (`shown`)."""
    parts = [f'{key}: {value}' for key, value in (detail or {}).items()
             if key != 'basis' and key not in shown]
    text = '; '.join(parts)
    return text if limit is None or len(text) <= limit else \
        text[:limit - 1] + '…'


class ActivityModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []
        self.names = {}
        #: Set by the panel: readings(row id) -> every reading of a record
        #: (Case.readings), for the Read by column's tooltip.
        self.readings = None
        self.layout = LAYOUTS[None]
        self._shown = ()

    def set_layout(self, category):
        """The columns of `category`'s tab (LAYOUTS; None = All)."""
        layout = LAYOUTS.get(category, LAYOUTS[None])
        if layout == self.layout:
            return False
        self.beginResetModel()
        self.layout = layout
        keys = []
        for name in layout:
            spec = _C[name][1]
            if spec.startswith('d:'):
                keys += spec[2:].split('|')
        self._shown = tuple(keys) + (('to', 'from') if 'party' in layout
                                     else ()) + (('app',) if 'app' in layout
                                                 else ())
        self.endResetModel()
        return True

    def column_of(self, name):
        """The column showing `name` (a LAYOUTS entry) now, else -1."""
        return self.layout.index(name) if name in self.layout else -1

    def widths(self):
        return [_C[name][2] for name in self.layout]

    def set_rows(self, rows, names):
        self.beginResetModel()
        self.rows, self.names = rows, names
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.layout)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole and \
                0 <= section < len(self.layout):
            return _C[self.layout[section]][0]
        return None

    def _name(self, column):
        return self.layout[column] if 0 <= column < len(self.layout) else ''

    def _cell(self, row, column):
        spec = _C[self._name(column)][1] if self._name(column) else ''
        detail = row.get('detail') or {}
        if spec == 'time':
            time = row.get('time_utc') or ''
            if time and row.get('time_local'):
                return f'{time} (local)'
            from trace_app.core.settings import alongside
            return alongside(time)
        if spec in ('what', 'subject', 'user', 'source'):
            return row.get(spec) or ''
        if spec == 'details':
            return detail_text(detail, 300, self._shown)
        if spec == 'read_by':
            return ', '.join(row.get('read_by') or [row.get('reader') or
                                                    'TRACE'])
        if spec == 'evidence':
            return self.names.get(row.get('evidence_id'), '')
        if spec == 'file':
            return row.get('source_path') or ''
        if spec == 'party':
            if detail.get('to') and not detail.get('from'):
                return f"→ {detail['to']}"
            if detail.get('from'):
                return f"← {detail['from']}"
            return ''
        if spec == 'app':
            return str(detail.get('app') or row.get('source') or '')
        if spec.startswith('d:'):
            for key in spec[2:].split('|'):
                value = row.get(key) if key in ('subject', 'source') \
                    else detail.get(key)
                if value not in (None, ''):
                    return str(value)
        return ''

    def _sort_value(self, row, column):
        text = self._cell(row, column)
        name = self._name(column)
        if name == 'time':
            return row.get('time_utc') or ''
        if name in _NUMERIC:
            number = _seconds(text) if name == 'duration' else None
            if number is None:
                try:
                    number = float(text)
                except ValueError:
                    number = None
            # Numbers first, in order; blanks and words after.
            return (0, number, '') if number is not None else (1, 0, text)
        return text.lower()

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        column = index.column()
        name = self._name(column)
        if role == Qt.DisplayRole:
            return self._cell(row, column)
        if role == SORT_ROLE:
            value = self._sort_value(row, column)
            # QVariant cannot compare tuples: numbers as zero-padded text.
            if isinstance(value, tuple):
                kind, number, text = value
                return f"{kind}{number + 1e12:030.6f}" if kind == 0 \
                    else f"1{text.lower()}"
            return value
        if role == Qt.ToolTipRole:
            if name == 'time' and row.get('time_local'):
                return ("Local time of the machine that wrote it; the source "
                        "keeps no time zone.")
            if name == 'time' and not row.get('time_utc'):
                return "The source keeps no time for this entry."
            if name == 'details':
                lines = [f'{k}: {v}' for k, v in
                         (row.get('detail') or {}).items()]
                return '\n'.join(lines) or None
            if name in ('source', 'app', 'browser'):
                return row.get('source_path') or None
            if name == 'read_by':
                return self._readings_tip(row)
            if name == 'file':
                return ("The file on the evidence this record was read "
                        "from; double-click goes to it.\n"
                        + (row.get('source_path') or ''))
            return self._cell(row, column) or None
        if role == Qt.UserRole:
            return row
        return None


    def _readings_tip(self, row):
        """Each tool's reading of the record, when more than one read it."""
        readers = row.get('read_by') or []
        if len(readers) < 2 or self.readings is None:
            return f"Read by {', '.join(readers) or 'TRACE'}"
        try:
            readings = self.readings(row['id'])
        except Exception:
            return f"Read by {', '.join(readers)}"
        lines = ["One record, read by " + ', '.join(readers) + ":"]
        for reading in readings:
            lines.append(f"\n{reading.get('reader') or 'TRACE'}: "
                         f"{reading.get('what') or ''} — "
                         f"{reading.get('subject') or ''}")
            lines.append(f"    {reading.get('time_utc') or 'no time'}"
                         f"    {reading.get('source_path') or ''}")
            module = (reading.get('detail') or {}).get('module')
            if module:
                lines.append(f"    {module}")
        return '\n'.join(lines)


class _NarrowProxy(QSortFilterProxyModel):
    """The table's sort, and -- after a click on a chart or a card -- only
    the records it chose (`set_only(ids)`; None = every record)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.only = None

    def set_only(self, ids):
        self.only = None if ids is None else set(ids)
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, _parent):
        if self.only is None:
            return True
        rows = self.sourceModel().rows
        return 0 <= source_row < len(rows) and \
            rows[source_row].get('id') in self.only


#: The views a tab offers (core/record_views.views_for): button text,
#: icon and what it shows.
_VIEWS = {
    record_views.TABLE: ("Table", "Icons/tabler/table.svg",
                         "Every record, one per row"),
    record_views.CHARTS: ("Charts", "Icons/tabler/chart-bar.svg",
                          "Records over time, by weekday and hour, and the "
                          "values that come up most -- click any of them "
                          "for its records"),
    record_views.ITEMS: ("Items", "Icons/tabler/layout-grid.svg",
                         "A card for each device, network, program, site, "
                         "person or account the records are about"),
}


#: The same records shown another way in Triage, said on the status line.
_ELSEWHERE = {
    'communication': " — also as threads in Triage ▸ Conversations "
                     "(right-click ▸ Show in Conversation)",
    'locations': " — also on Triage ▸ Map (right-click ▸ Show on Map)",
}


def _Load(folder, generation, evidence_id, category, text, reader=None,
          only=False, parent=None):
    """One read of the case's activity."""
    return CaseQuery(
        folder, generation,
        lambda connection: query_user_activity(
            connection, evidence_id, category, text, limit=SHOWN_LIMIT,
            reader=reader, only_reader=only),
        [], 'activity', parent)


class ActivityPanel(QWidget):
    """The Activity tab."""

    row_selected = Signal(dict)
    row_activated = Signal(dict)
    row_menu_requested = Signal(dict, object)
    run_requested = Signal()
    #: A Recycle Bin row's content, to be shown in Triage > Deleted files.
    deleted_requested = Signal(dict)
    #: A message/call row, to be shown in its thread (Triage ▸
    #: Conversations), and a located row on Triage ▸ Map: the same records,
    #: shown another way.
    conversation_requested = Signal(dict)
    map_requested = Signal(dict)
    #: A row of a module artifact TRACE did not sort (the Others
    #: group): the same payloads as the Modules tab's rows.
    module_row_selected = Signal(dict)
    module_row_activated = Signal(dict)
    module_row_menu_requested = Signal(dict, object)
    module_artifact_report_requested = Signal(dict, dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("activityPanel")
        self.case = None
        self.evidence_id = None
        self.category = None
        self._names = {}
        self._generation = 0
        self._loads = KeptThreads(self)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.toolbar = QToolBar()
        prepare_toolbar(self.toolbar)
        self.status_label = ElidedLabel()
        self.status_label.setObjectName("triageStatus")
        self.status_label.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Preferred)
        self.toolbar.addWidget(self.status_label)
        self.evidence_filter = QComboBox()
        self.evidence_filter.setObjectName("triageEvidenceFilter")
        self.evidence_filter.setToolTip("Show activity from every image in "
                                        "the case, or from one.")
        self.evidence_filter.currentIndexChanged.connect(self._filter_changed)
        self.toolbar.addWidget(self.evidence_filter)
        # Who read it: TRACE's own Activity module, an external module
        # (iLEAPP...), or a record only one of them found.
        self.reader_filter = QComboBox()
        self.reader_filter.setObjectName("triageEvidenceFilter")
        self.reader_filter.setToolTip(
            "Records read by every reader, by one (with what others read "
            "too), or only by one -- what the other tools did not find.")
        self.reader_filter.currentIndexChanged.connect(self._filter_changed)
        self.reader_filter_action = self.toolbar.addWidget(
            self.reader_filter)
        self.run_button = QPushButton("Read Activity")
        self.run_button.setObjectName("triageRunButton")
        self.run_button.setToolTip("Analysis ▸ Run Analysis Modules, with "
                                   "Windows activity and browser history")
        self.run_button.clicked.connect(self.run_requested.emit)
        # Table, Charts, Items: how this tab's records are shown.
        self.view_mode = record_views.TABLE
        self.view_buttons = {}
        switch = QWidget()
        switch_row = QHBoxLayout(switch)
        switch_row.setContentsMargins(6, 0, 6, 0)
        switch_row.setSpacing(0)
        for key, (label, icon, tip) in _VIEWS.items():
            button = QToolButton()
            button.setObjectName("timelineViewSwitch")
            button.setText(label)
            button.setIcon(icons.icon(icon))
            button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            button.setToolTip(tip)
            button.setCheckable(True)
            button.setAutoExclusive(True)
            button.clicked.connect(
                lambda _c=False, k=key: self.set_view(k, remember=True))
            self.view_buttons[key] = button
            switch_row.addWidget(button)
        self.view_buttons[record_views.TABLE].setChecked(True)
        self.view_switch_action = self.toolbar.addWidget(switch)
        self.toolbar.addWidget(self.run_button)
        outer.addWidget(self.toolbar)

        layout = QVBoxLayout()
        # Tabs and table edge to edge: margins here showed as wide empty
        # bands around the tab rows.
        layout.setContentsMargins(2, 2, 2, 0)
        layout.setSpacing(0)
        outer.addLayout(layout)

        self.tabs = GroupedTabs(GROUPS, name='activity')
        self._keys = [None] + [key for key, _label in CATEGORIES]
        self._labels = ['All'] + [label for _key, label in CATEGORIES]
        for key, label in zip(self._keys, self._labels):
            self.tabs.addTab(icons.icon(icons.ACTIVITY_CATEGORIES[key]),
                             label, group=GROUP_OF.get(key))
        self.tabs.currentChanged.connect(self._tab_changed)
        self.filter_input = QLineEdit()
        self.filter_input.setObjectName("activityFilter")
        self.filter_input.setPlaceholderText("Filter…")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.setMaximumWidth(260)
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(300)
        self._filter_timer.timeout.connect(self.refresh)
        self.filter_input.textChanged.connect(
            lambda _t: self._filter_timer.start())
        # Under the toolbar's last control (Read Activity), which Qt's
        # toolbar layout ends 13 px short of the edge; this layout's own
        # margin is 2.
        self.tabs.set_corner_widget(self.filter_input, inset=11)
        layout.addWidget(self.tabs)

        # After a click on a chart or a card: the records it chose, and the
        # way back.
        self.narrow_bar = QWidget()
        narrow_row = QHBoxLayout(self.narrow_bar)
        narrow_row.setContentsMargins(2, 4, 2, 4)
        self.narrow_chip = QToolButton()
        self.narrow_chip.setObjectName("timelinePivotChip")
        self.narrow_chip.setToolTip("Show every record again")
        self.narrow_chip.clicked.connect(self.clear_narrow)
        narrow_row.addWidget(self.narrow_chip)
        narrow_row.addStretch(1)
        self.narrow_bar.setVisible(False)
        self._narrowed_from = None
        layout.addWidget(self.narrow_bar)

        self.model = ActivityModel(self)
        self.proxy = _NarrowProxy(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(SORT_ROLE)
        self.table = QTableView()
        self.table.setObjectName("activityTable")
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.DescendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        self._fit_columns()
        self.table.selectionModel().currentRowChanged.connect(
            lambda current, _previous: self._emit(current, self.row_selected))
        self.table.clicked.connect(
            lambda index: self._emit(index, self.row_selected))
        self.table.doubleClicked.connect(
            lambda index: self._emit(index, self.row_activated))
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.views = QStackedWidget()
        self.views.addWidget(self.table)
        self.overview = RecordOverview()
        self.overview.narrow_requested.connect(self.narrow)
        self.views.addWidget(self.overview)
        self.items_view = ItemsView()
        self.items_view.narrow_requested.connect(self.narrow)
        self.items_view.item_selected.connect(self.row_selected.emit)
        self.items_view.item_activated.connect(self.row_activated.emit)
        self.views.addWidget(self.items_view)
        # The view drawn last and the rows it was drawn from; big ones are
        # worked out in a child process (RecordViewTask).
        self._shown_mode = self._shown_rows = None
        self._view_generation = 0
        self._view_tasks = KeptThreads(self)
        self._row_params = None
        self.module_runs = []
        self._module_tabs = {}        # tab index -> ModuleRecordsView
        self.module_views = []
        for roles, _label, _icon in MODULE_TABS:
            view = ModuleRecordsView(roles)
            view.row_selected.connect(self.module_row_selected.emit)
            view.row_activated.connect(self.module_row_activated.emit)
            view.row_menu_requested.connect(
                self.module_row_menu_requested.emit)
            view.artifact_report_requested.connect(
                self.module_artifact_report_requested.emit)
            self.views.addWidget(view)
            self.module_views.append(view)
        layout.addWidget(self.views, 1)

        chosen = config_store.get('Activity', self._view_key(),
                                  record_views.TABLE)
        self.set_view(chosen)
        self.set_case(None)

    # --- what to show -----------------------------------------------------

    def set_case(self, case):
        self.case = case
        self._names = {}
        if case is not None:
            self._names = {r['id']: r.get('display_name')
                           or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                           for r in case.evidence()}
        self.evidence_filter.blockSignals(True)
        self.evidence_filter.clear()
        self.evidence_filter.addItem("All evidence", None)
        for evidence_id, name in sorted(self._names.items(),
                                        key=lambda kv: kv[1].lower()):
            self.evidence_filter.addItem(name, evidence_id)
        index = self.evidence_filter.findData(self.evidence_id)
        self.evidence_filter.setCurrentIndex(index if index >= 0 else 0)
        self.evidence_id = self.evidence_filter.currentData()
        self.evidence_filter.blockSignals(False)
        self.evidence_filter.setVisible(len(self._names) > 1)
        self._fill_readers()
        self.model.readings = case.readings if case is not None else None
        self.run_button.setEnabled(case is not None)
        self.set_module_runs(self.module_runs if case is not None else [])
        self.refresh()

    def _fill_readers(self):
        current = self.reader_filter.currentData()
        readers = []
        if self.case is not None:
            try:
                readers = self.case.activity_readers()
            except sqlite3.Error:
                readers = []
        self.reader_filter.blockSignals(True)
        self.reader_filter.clear()
        self.reader_filter.addItem("Every reader", None)
        for name in readers:
            self.reader_filter.addItem(f"Read by {name}", f"{name}|")
        if len(readers) > 1:
            for name in readers:
                # Strings, not tuples: findData compares a Python object
                # by identity, so a tuple chosen before is never found.
                self.reader_filter.addItem(f"Only read by {name}",
                                           f"{name}|only")
        index = self.reader_filter.findData(current)
        self.reader_filter.setCurrentIndex(max(index, 0))
        self.reader_filter.blockSignals(False)
        self.reader_filter_action.setVisible(len(readers) > 1)

    def reader_choice(self):
        """(reader or None, only that reader?) chosen in the filter."""
        chosen = self.reader_filter.currentData()
        if not chosen:
            return None, False
        name, _sep, only = chosen.rpartition('|')
        return name, only == 'only'

    def set_evidence_filter(self, evidence_id):
        index = self.evidence_filter.findData(evidence_id)
        self.evidence_filter.setCurrentIndex(index if index >= 0 else 0)

    def show_category(self, category):
        """Bring a category's sub-tab forward ('programs', ... or None)."""
        index = self._keys.index(category) if category in self._keys else 0
        if self.tabs.currentIndex() == index:
            self.refresh()
        self.tabs.setCurrentIndex(index)

    @property
    def loading(self):
        return bool(self._loads)

    def _filter_changed(self, _index):
        self.evidence_id = self.evidence_filter.currentData()
        self.set_module_runs(self.module_runs)
        self.refresh()

    def _fit_columns(self):
        for column, width in enumerate(self.model.widths()):
            self.table.setColumnWidth(column, width)

    def _tab_changed(self, index):
        self.category = self._keys[index] if 0 <= index < len(self._keys) \
            else None
        if self.model.set_layout(self.category):
            self._fit_columns()
            self.table.sortByColumn(0, Qt.DescendingOrder)
        view = self._module_tabs.get(index)
        self._set_narrow(None)
        self._shown_mode = self._shown_rows = None
        if view is not None:
            self.view_switch_action.setVisible(False)
            self.views.setCurrentWidget(view)
        else:
            self.view_switch_action.setVisible(True)
            offered = record_views.views_for(self.category)
            for key, button in self.view_buttons.items():
                button.setVisible(key in offered)
            chosen = config_store.get('Activity', self._view_key(),
                                      record_views.TABLE)
            self.set_view(chosen if chosen in offered
                          else record_views.TABLE)
        self.refresh()

    # --- Table, Charts, Items --------------------------------------------

    def _view_key(self):
        return f"view_{self.category or 'all'}"

    def set_view(self, mode, remember=False):
        """Show this tab's records as `mode` (core/record_views: table,
        charts, items); `remember` keeps the choice for the category."""
        if mode not in record_views.views_for(self.category):
            mode = record_views.TABLE
        self.view_mode = mode
        self.view_buttons[mode].setChecked(True)
        if remember:
            config_store.set_value('Activity', self._view_key(), mode)
            if mode != record_views.TABLE:
                self._set_narrow(None)
        if self._module_tabs.get(self.tabs.currentIndex()) is not None:
            return
        self.views.setCurrentWidget(
            {record_views.CHARTS: self.overview,
             record_views.ITEMS: self.items_view}.get(mode, self.table))
        self._draw_view()

    def _draw_view(self):
        """Work out the chosen view from the rows held (once per load and
        view): a few thousand rows at once, more in a child process."""
        mode, rows = self.view_mode, self.model.rows
        if mode == record_views.TABLE or (
                self._shown_mode == mode and self._shown_rows is rows):
            return
        self._shown_mode, self._shown_rows = mode, rows
        label = self._labels[self._keys.index(self.category)] \
            if self.category in self._keys else ''
        label = label if self.category else ''
        self._view_generation += 1
        for task in self._view_tasks.values():
            task.stop()             # kept until it has ended
        if len(rows) > INLINE_ROWS and self.case is not None and \
                self._row_params is not None:
            from trace_app.ui.viewers.record_views import (RecordViewTask,
                                                           _zone)
            params = dict(self._row_params, view=mode, zone=_zone(),
                          limit=SHOWN_LIMIT)
            task = RecordViewTask(params, self)
            generation = self._view_generation
            task.done.connect(
                lambda result, g=generation, m=mode, l=label:
                self._view_done(g, m, l, result))
            self._view_tasks[generation] = task
            if mode == record_views.CHARTS:
                self.overview.show_working(len(rows))
            else:
                self.items_view.show_working(len(rows), self.category)
            task.start()
            return
        if mode == record_views.CHARTS:
            self.overview.show_rows(rows, self.category, label)
        else:
            self.items_view.show_rows(rows, self.category, label,
                                      self._names)

    def _view_done(self, generation, mode, label, result):
        if generation != self._view_generation:
            return
        if isinstance(result, Exception) or not result:
            logger.error("Could not work out the %s view: %s", mode, result)
            self._shown_mode = None
            message = "Could not work out this view; the log says why."
            if mode == record_views.CHARTS:
                self.overview.summary.setText(message)
            else:
                self.items_view.status.setText(message)
            return
        if mode == record_views.CHARTS:
            self.overview.show_result(result['overview'], self.category,
                                      label)
        else:
            self.items_view.show_items(result['items'], result['unnamed'],
                                       result['rows'], self.category,
                                       self._names)

    def narrow(self, ids, label):
        """The table, showing only rows `ids` (from a chart or a card);
        the chip above it goes back to where the click came from."""
        if not ids:
            return
        self._narrowed_from = self.view_mode
        self._set_narrow(ids, label)
        self.view_mode = record_views.TABLE
        self.view_buttons[record_views.TABLE].setChecked(True)
        self.views.setCurrentWidget(self.table)

    def clear_narrow(self):
        back = self._narrowed_from
        self._set_narrow(None)
        if back and back != record_views.TABLE:
            self.set_view(back)

    def _set_narrow(self, ids, label=''):
        self.proxy.set_only(ids)
        if ids is None:
            self._narrowed_from = None
            self.narrow_bar.setVisible(False)
            return
        shown = self.proxy.rowCount()
        self.narrow_chip.setText(f"{label} — {shown:,} record(s)  ✕")
        self.narrow_bar.setVisible(True)

    # --- what external modules read and TRACE did not sort ---------------

    def set_module_runs(self, runs):
        """The window's module run dicts (MainWindow._module_runs): the
        Others group lists their artifacts TRACE did not sort as
        evidence, read from each tool's database when one is chosen. The
        group is there only while there is something in it."""
        self.module_runs = list(runs or ())
        counts = [count_hidden(self.module_runs, roles, self.evidence_id)
                  for roles, _label, _icon in MODULE_TABS]
        if self.case is None:
            counts = [(0, 0)] * len(MODULE_TABS)
        if any(artifacts for artifacts, _rows in counts):
            if not self._module_tabs:
                for view, (_roles, label, icon) in zip(self.module_views,
                                                       MODULE_TABS):
                    index = self.tabs.addTab(icons.icon(icon), label,
                                             group='modules')
                    self._module_tabs[index] = view
            for (index, view), (_roles, label, _icon), (artifacts, _rows) in \
                    zip(sorted(self._module_tabs.items()), MODULE_TABS,
                        counts):
                self.tabs.setTabText(index, f"{label} ({artifacts:,})")
                view.source_of = getattr(self, 'module_source_of', None)
                view.set_runs(self.module_runs, self.evidence_id)
            self.tabs.setGroupText(
                'modules', f"Others "
                           f"({sum(a for a, _r in counts):,})")
        elif self._module_tabs:
            for view in self.module_views:
                view.shutdown()
            self._module_tabs = {}
            self.tabs.remove_group('modules')
            self.view_switch_action.setVisible(True)
            self.set_view(self.view_mode)
        self._module_counts = counts

    def _module_status(self, view):
        artifacts, tools = [], set()
        for run in self.module_runs:
            found = hidden_artifacts(run, view.roles, self.evidence_id)
            artifacts += found
            if found:
                tools.add(run['tool'])
        tools = sorted(tools)
        rows = sum(a.get('record_count') or 0 for a in artifacts)
        what = ("device telemetry -- logs and samples"
                if 'telemetry' in view.roles else
                "settings, device information, caches and other records")
        return (f"{len(artifacts):,} artifact(s), {rows:,} row(s) "
                f"{' and '.join(tools)} read that TRACE did not sort as "
                f"evidence ({what}). Read from the tool's own database -- "
                f"nothing is copied into the case. Right-click an artifact "
                f"in the Modules tab to sort it as evidence.")

    def refresh(self):
        """Reload the counts and the rows (rows on a thread)."""
        self._update_counts()
        view = self._module_tabs.get(self.tabs.currentIndex())
        if view is not None:
            # A load of another tab still under way must not write its
            # count over this one's status.
            self._generation += 1
            self.status_label.setText(self._module_status(view))
            return
        # New rows: what a chart or card chose may not be among them.
        if self.proxy.only is not None:
            self.clear_narrow()
        if self.case is None:
            self.model.set_rows([], {})
            self._draw_view()
            self.status_label.setText("Activity is kept with a case. "
                                      "File ▸ New Case starts one.")
            return
        self._generation += 1
        reader, only = self.reader_choice()
        # What the rows are, for a view worked out in a child process.
        self._row_params = {
            'case_folder': self.case.folder, 'evidence_id': self.evidence_id,
            'category': self.category,
            'text': self.filter_input.text().strip(), 'reader': reader,
            'only': only}
        load = _Load(self.case.folder, self._generation, self.evidence_id,
                     self.category, self.filter_input.text().strip(),
                     reader, only, self)
        load.loaded.connect(self._loaded)
        self._loads[self._generation] = load
        self.status_label.setText("Loading…")
        load.start()

    def _loaded(self, generation, rows):
        if generation != self._generation:
            return
        self.model.set_rows(rows, self._names)
        self.table.sortByColumn(self.table.horizontalHeader()
                                .sortIndicatorSection(),
                                self.table.horizontalHeader()
                                .sortIndicatorOrder())
        if self._module_tabs.get(self.tabs.currentIndex()) is None:
            self._draw_view()
        if rows:
            more = (f" — the newest {SHOWN_LIMIT:,} shown; filter to narrow"
                    if len(rows) >= SHOWN_LIMIT else '')
            hidden = sum(a for a, _r in getattr(self, '_module_counts', ()))
            elsewhere = _ELSEWHERE.get(self.category, '') or (
                f" — {hidden:,} more artifact(s) from external modules "
                f"under Others" if hidden and self.category is None
                else '')
            self.status_label.setText(f"{len(rows):,} record(s){more}"
                                      + elsewhere)
        elif self._summary:
            self.status_label.setText("Nothing matches.")
        else:
            self.status_label.setText(
                "Nothing read yet. Read Activity runs Windows activity and "
                "browser history from Analysis ▸ Run Analysis Modules.")
        self._reveal_pending()

    def reveal(self, row_id, category=None):
        """Select activity row `row_id` (from Triage's Show in Activity):
        on its category's sub-tab, every reader, no text filter."""
        self._pending = row_id
        if self.filter_input.text():
            self.filter_input.blockSignals(True)
            self.filter_input.setText('')
            self.filter_input.blockSignals(False)
        if self.reader_filter.currentIndex() != 0:
            self.reader_filter.blockSignals(True)
            self.reader_filter.setCurrentIndex(0)
            self.reader_filter.blockSignals(False)
        self.show_category(category)

    def _reveal_pending(self):
        row_id = getattr(self, '_pending', None)
        if row_id is None or self.loading and not self.model.rows:
            return
        for number, row in enumerate(self.model.rows):
            if row.get('id') == row_id:
                self._pending = None
                # A row is shown in the table, whatever view was chosen.
                self._set_narrow(None)
                if self.view_mode != record_views.TABLE:
                    self.set_view(record_views.TABLE)
                index = self.proxy.mapFromSource(self.model.index(number, 0))
                self.table.selectRow(index.row())
                self.table.scrollTo(index, QAbstractItemView.PositionAtCenter)
                return

    def _update_counts(self):
        self._summary = {}
        if self.case is not None:
            try:
                self._summary = self.case.user_activity_summary(
                    self.evidence_id)
            except sqlite3.Error as exc:
                logger.error("Could not count activity: %s", exc)
        total = sum(self._summary.values())
        groups = dict.fromkeys((key for key, _ in GROUPS), 0)
        for index, key in enumerate(self._keys):
            count = total if key is None else self._summary.get(key, 0)
            self.tabs.setTabText(index, f"{self._labels[index]} ({count:,})")
            if key is not None:
                groups[GROUP_OF.get(key, 'communication')] += count
        groups['all'] = total
        for key, label in GROUPS:
            if key != 'modules':      # set_module_runs counts that one
                self.tabs.setGroupText(key, f"{label} ({groups[key]:,})")

    @property
    def count(self):
        return sum(getattr(self, '_summary', {}).values())

    # --- actions ----------------------------------------------------------

    def _emit(self, index, signal):
        if index is None or not index.isValid():
            return
        row = self.proxy.data(index, Qt.UserRole)
        if row:
            signal.emit(row)

    def _menu(self, point):
        index = self.table.indexAt(point)
        if not index.isValid():
            return
        row = self.proxy.data(index, Qt.UserRole)
        menu = QMenu(self)
        copy_subject = menu.addAction("Copy Subject")
        copy_row = menu.addAction("Copy Row")
        menu.addSeparator()
        source = menu.addAction("Show Source File in Listing")
        source.setEnabled(bool(row.get('source_ref')))
        from trace_app.core import conversations, geo
        conversation = place = None
        if conversations.is_message(row):
            conversation = menu.addAction("Show in Conversation")
        if geo.position(row.get('detail')) is not None:
            place = menu.addAction("Show on Map")
        content = None
        if row.get('category') == 'recycle':
            # The deleted file itself, and how much of it is left.
            content = menu.addAction("Show Content in Deleted Files")
            content.setEnabled(bool(row.get('recycle_content')))
            if not row.get('recycle_content'):
                content.setToolTip("Run Analysis ▸ Deleted files first, or "
                                   "the content is still in the bin")
        chosen = show_menu(menu, self.table.viewport().mapToGlobal(point))
        if chosen is not None and chosen == content:
            self.deleted_requested.emit(row['recycle_content'])
            return
        if chosen is not None and chosen == conversation:
            self.conversation_requested.emit(row)
            return
        if chosen is not None and chosen == place:
            self.map_requested.emit(row)
            return
        if chosen == copy_subject:
            QGuiApplication.clipboard().setText(row.get('subject') or '')
        elif chosen == copy_row:
            QGuiApplication.clipboard().setText('\t'.join([
                row.get('time_utc') or '', row.get('what') or '',
                row.get('subject') or '', row.get('user') or '',
                json.dumps(row.get('detail') or {}, ensure_ascii=False),
                row.get('source') or '', row.get('source_path') or '']))
        elif chosen == source:
            self.row_activated.emit(row)

    def shutdown(self):
        self._loads.clear()
        for task in self._view_tasks.values():
            task.stop()
        self._view_tasks.clear()
        for view in self.module_views:
            view.shutdown()
