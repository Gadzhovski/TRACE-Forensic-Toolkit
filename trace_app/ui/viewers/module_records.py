"""What external modules read that TRACE did not sort as evidence, in the
Activity tab (its "Others" group).

The Activity tab's own rows are records TRACE sorted (core/modules/bridge
copies an evidence artifact's rows into the case, linked to the tool's
row). Everything else a tool read -- settings, device information, caches
('other') and device telemetry (unified log, power and health samples) --
stays where the tool wrote it, `_lava_artifacts.db`, and is read from there
here, a page at a time (modules_panel.ArtifactModel): nothing is copied.
Left, run > category > artifact; right, the chosen artifact's rows in the
tool's own columns. Rows are module rows ('mod:' refs), so the window's
Modules-row handlers preview, open, tag and report them.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView,
                               QMenu, QSplitter, QStackedWidget, QTableView,
                               QToolButton, QTreeWidgetItem, QVBoxLayout,
                               QWidget)

from trace_app.infra import config_store
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui import icons
from trace_app.ui.viewers.modules_panel import ArtifactModel, row_payload
from trace_app.ui.viewers.record_views import ArtifactChart
from trace_app.ui.widgets.tree_branch import BranchTreeWidget


def hidden_artifacts(run, roles, evidence_id=None):
    """A run's artifacts with one of `roles` that are not shown elsewhere
    (a newer run's copy of the same rows supersedes one), with rows --
    those the case sends to Activity (Settings ▸ Results). Evidence the
    case keeps out of Activity is browsed here as other records."""
    from trace_app.core.modules import destinations
    if run.get('status') != 'complete' or (
            evidence_id is not None and run.get('evidence_id') != evidence_id):
        return []
    evidence_listed = not destinations.goes_to(
        {'role': destinations.EVIDENCE}, 'activity')
    out = []
    for artifact in run.get('artifacts') or ():
        role = destinations.role_of(artifact)
        if role == destinations.EVIDENCE:
            if not evidence_listed:
                continue
            role = destinations.OTHER
        elif not destinations.goes_to(artifact, 'activity'):
            continue
        if role in roles and not artifact.get('superseded_by') and                 (artifact.get('record_count') or 0):
            out.append(artifact)
    return out


def count_hidden(runs, roles, evidence_id=None):
    """(artifacts, rows) of `roles` over `runs`."""
    artifacts = [a for run in runs
                 for a in hidden_artifacts(run, roles, evidence_id)]
    return len(artifacts), sum(a.get('record_count') or 0 for a in artifacts)


class ModuleRecordsView(QWidget):
    """Run > category > artifact beside the artifact's rows."""

    row_selected = Signal(dict)
    row_activated = Signal(dict)
    row_menu_requested = Signal(dict, object)
    #: (run, artifact): add the whole artifact to the report.
    artifact_report_requested = Signal(dict, dict)

    def __init__(self, roles, parent=None):
        super().__init__(parent)
        self.roles = tuple(roles)
        self.runs = []
        self.evidence_id = None
        #: (run dict, staged path) -> the evidence file it came from; set
        #: by the window, as on the Modules tab.
        self.source_of = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(Qt.Horizontal)
        self.tree = BranchTreeWidget()
        self.tree.setObjectName("triageTable")
        self.tree.setHeaderHidden(True)
        self.tree.currentItemChanged.connect(self._chosen)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        split.addWidget(self.tree)

        self.model = ArtifactModel(self)
        self.model.payload_of = self.payload
        self.table = QTableView()
        self.table.setObjectName("modulesRows")
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setWordWrap(False)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.table.doubleClicked.connect(
            lambda index: self.row_activated.emit(self.payload(index.row())))
        self.table.selectionModel().currentRowChanged.connect(
            lambda current, _old: current.isValid() and self.row_selected.emit(
                self.payload(current.row())))
        # Rows, or the artifact charted: a measurement over time (battery,
        # steps, heart rate), spans of time (screen on, locked, app in
        # use) or rows per time -- whatever its columns allow.
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(2)
        switch = QHBoxLayout()
        switch.setContentsMargins(2, 2, 2, 0)
        switch.setSpacing(0)
        self.view_buttons = {}
        for key, label, icon, tip in (
                ('table', "Table", "Icons/tabler/table.svg",
                 "The artifact's rows, as the tool wrote them"),
                ('chart', "Chart", "Icons/tabler/chart-bar.svg",
                 "The artifact over time: its measurements, its spans of "
                 "time, or how many rows when")):
            button = QToolButton()
            button.setObjectName("timelineViewSwitch")
            button.setText(label)
            button.setIcon(icons.icon(icon))
            button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            button.setToolTip(tip)
            button.setCheckable(True)
            button.setAutoExclusive(True)
            button.clicked.connect(lambda _c=False, k=key: self.set_view(k))
            self.view_buttons[key] = button
            switch.addWidget(button)
        switch.addStretch(1)
        right_layout.addLayout(switch)
        self.pages = QStackedWidget()
        self.pages.addWidget(self.table)
        self.chart = ArtifactChart()
        self.chart.row_requested.connect(self._chart_row)
        self.pages.addWidget(self.chart)
        right_layout.addWidget(self.pages, 1)
        split.addWidget(right)
        self.view = config_store.get('Activity', 'others_view', 'table')
        if self.view not in self.view_buttons:
            self.view = 'table'
        self.view_buttons[self.view].setChecked(True)
        self.pages.setCurrentWidget(self.chart if self.view == 'chart'
                                    else self.table)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 3)
        split.setSizes([280, 800])
        layout.addWidget(split)

    def set_runs(self, runs, evidence_id=None):
        """Show the hidden artifacts of `runs` (the window's run dicts),
        of one evidence item or all. The artifact shown stays when it is
        still listed; nothing is read until an artifact is chosen."""
        chosen = self._chosen_key()
        self.runs, self.evidence_id = runs, evidence_id
        self.tree.clear()
        for run_index, run in enumerate(runs):
            artifacts = hidden_artifacts(run, self.roles, evidence_id)
            if not artifacts:
                continue
            what = (run.get('input') or {}).get('label') or run['evidence']
            rows = sum(a.get('record_count') or 0 for a in artifacts)
            head = QTreeWidgetItem([f"{run['tool']} {run['version']} — "
                                    f"{what} ({rows:,})"])
            head.setIcon(0, icons.module_logo(run['tool']))
            head.setToolTip(0, f"{run['evidence']} · started "
                               f"{run.get('started') or ''}")
            self.tree.addTopLevelItem(head)
            position = {id(a): i for i, a in enumerate(run['artifacts'])}
            groups = {}
            for artifact in artifacts:
                groups.setdefault(artifact['category'], []).append(artifact)
            for category, members in sorted(groups.items()):
                count = sum(a.get('record_count') or 0 for a in members)
                group = QTreeWidgetItem([f"{category} ({count:,})"])
                category_icon = icons.leapp_category_icon(members)
                if category_icon is not None:
                    group.setIcon(0, category_icon)
                head.addChild(group)
                for artifact in sorted(members, key=lambda a: a['name']):
                    node = QTreeWidgetItem([
                        f"{artifact['name']} "
                        f"({artifact.get('record_count') or 0:,})"])
                    node.setIcon(0, icons.leapp_icon(artifact))
                    node.setToolTip(0, (artifact.get('route_why') or '')
                                    + "\nRead from the tool's own database; "
                                      "right-click it in the Modules tab "
                                      "to sort it as evidence.")
                    # Indices, never the dicts: PySide copies a dict set as
                    # item data into a Qt map (CLAUDE.md, Modules tab).
                    node.setData(0, Qt.UserRole,
                                 (run_index, position[id(artifact)]))
                    group.addChild(node)
            head.setExpanded(True)
        if not (chosen and self._select(chosen)):
            self.model.show(None, None)
            self._charted = None
            self.chart.show_artifact(None, None)

    def _chosen_key(self):
        artifact = self.model.artifact
        run = self.model.run
        return (run['key'], artifact['tablename']) if artifact else None

    def _select(self, key):
        for top in range(self.tree.topLevelItemCount()):
            head = self.tree.topLevelItem(top)
            for g in range(head.childCount()):
                group = head.child(g)
                for c in range(group.childCount()):
                    node = group.child(c)
                    run, artifact = self._item(node)
                    if artifact and (run['key'], artifact['tablename']) == key:
                        self.tree.setCurrentItem(node)
                        return True
        return False

    def _item(self, item):
        data = item.data(0, Qt.UserRole) if item is not None else None
        if not isinstance(data, (tuple, list)) or len(data) != 2:
            return None, None
        run_index, artifact_index = data
        if not 0 <= run_index < len(self.runs):
            return None, None
        run = self.runs[run_index]
        artifacts = run.get('artifacts') or []
        if not 0 <= artifact_index < len(artifacts):
            return None, None
        return run, artifacts[artifact_index]

    def _chosen(self, current, _previous):
        run, artifact = self._item(current)
        if artifact is None:
            return
        self.model.show(run, artifact)
        for column in range(self.model.columnCount()):
            self.table.setColumnWidth(column, 160)
        self._charted = None
        if self.view == 'chart':
            self._chart_shown()

    def set_view(self, view):
        """'table' or 'chart', kept for every artifact."""
        self.view = view
        self.view_buttons[view].setChecked(True)
        config_store.set_value('Activity', 'others_view', view)
        self.pages.setCurrentWidget(self.chart if view == 'chart'
                                    else self.table)
        if view == 'chart':
            self._chart_shown()

    def _chart_shown(self):
        key = self._chosen_key()
        if key == getattr(self, '_charted', None):
            return
        self._charted = key
        self.chart.show_artifact(self.model.run, self.model.artifact)

    def _chart_row(self, rowid):
        """A span clicked on the chart: its row, as the table gives one."""
        from trace_app.core.modules import lava
        connection = self.model.connection
        if connection is None:
            return
        try:
            values = lava.row(connection, self.model.artifact, rowid)
        except Exception:
            values = None
        if values is None:
            return
        one = ArtifactModel(self)
        one.run, one.artifact = self.model.run, self.model.artifact
        one.media, one.rows = self.model.media, [(rowid, values)]
        self.row_selected.emit(row_payload(one, 0, self.source_of))

    def _tree_menu(self, point):
        from trace_app.ui.widgets.context_menus import show_menu
        run, artifact = self._item(self.tree.itemAt(point))
        if artifact is None:
            return
        menu = QMenu(self)
        menu.addAction(icons.icon(icons.REPORT),
                       "Add Artifact to Report").triggered.connect(
            lambda: self.artifact_report_requested.emit(run, artifact))
        show_menu(menu, self.tree.viewport().mapToGlobal(point))

    def payload(self, row):
        return row_payload(self.model, row, self.source_of)

    def selected_payloads(self):
        rows = sorted({index.row() for index in
                       self.table.selectionModel().selectedRows()})
        return [self.payload(row) for row in rows]

    def _menu(self, point):
        index = self.table.indexAt(point)
        if index.isValid():
            self.row_menu_requested.emit(
                self.payload(index.row()),
                self.table.viewport().mapToGlobal(point))

    def shutdown(self):
        """Let go of the tool's database (Windows deletes no open file)."""
        self.model.show(None, None)
        self.chart.shutdown()
        self._charted = None
