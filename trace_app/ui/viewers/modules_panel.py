"""The Modules tab: external tools' runs and what they extracted
(core/modules: iLEAPP, aLEAPP...).

Left, each run -- tool and version, image, when, how it ended -- with its
artifacts by category; right, the chosen artifact's rows, read from the
tool's own database (_lava_artifacts.db, read-only) a page at a time.
Times are UTC, with the display zone beside them when one is set; a media
column names the file. A row's payload carries its module ref
(case.make_module_ref), so tags, bookmarks, notes and report picks work on
it as on any file, and the file it came from (through the run's staging
manifest) for previewing and Show Source in Listing.
"""

import os

from PySide6.QtCore import (QAbstractTableModel, QModelIndex, Qt, Signal)
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox,
                               QHeaderView,
                               QLineEdit, QMenu, QPushButton, QSizePolicy,
                               QSplitter, QStackedWidget, QTableView,
                               QTextBrowser, QToolBar,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from trace_app.core.modules import lava
from trace_app.infra.constants import TABLE_ROW_HEIGHT
from trace_app.ui import icons
from trace_app.ui.widgets.context_menus import show_menu
from trace_app.ui.widgets.elided_label import ElidedLabel
from trace_app.ui.widgets.toolbars import prepare_toolbar
from trace_app.ui.widgets.tree_branch import BranchTreeWidget

PAGE = 500


class ArtifactModel(QAbstractTableModel):
    """One artifact's rows, fetched PAGE at a time as the view scrolls."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.run = None
        self.artifact = None
        self.connection = None
        self.media = {}
        self.rows = []
        self.total = 0
        #: row -> the payload a view's handlers take (row_payload); None
        #: asks the parent's payload().
        self.payload_of = None

    def show(self, run, artifact):
        self.beginResetModel()
        self._close()
        self.run, self.artifact, self.rows = run, artifact, []
        self.total = 0
        if artifact is not None:
            try:
                self.connection = lava.connect(run['report'])
                self.media = lava.media(self.connection)
                # The tool's own count: count(*) over iLEAPP's 21-million-
                # row unified log held the window for seconds.
                self.total = artifact.get('record_count')
                if self.total is None:
                    self.total = lava.count(self.connection, artifact)
                self.rows = lava.rows(self.connection, artifact,
                                      limit=PAGE, after=-2 ** 63)
            except Exception:
                self.connection, self.rows, self.total = None, [], 0
        self.endResetModel()

    def _close(self):
        if self.connection is not None:
            try:
                self.connection.close()
            except Exception:
                pass
        self.connection = None

    def columns(self):
        return self.artifact['columns'] if self.artifact else []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns())

    def canFetchMore(self, parent=QModelIndex()):
        return not parent.isValid() and len(self.rows) < self.total

    def fetchMore(self, parent=QModelIndex()):
        if self.connection is None:
            return
        # By rowid, not offset: deep in a big table each OFFSET page
        # stepped over every row before it.
        page = lava.rows(self.connection, self.artifact, limit=PAGE,
                         after=self.rows[-1][0] if self.rows else -2 ** 63)
        if not page:
            self.total = len(self.rows)
            return
        self.beginInsertRows(QModelIndex(), len(self.rows),
                             len(self.rows) + len(page) - 1)
        self.rows.extend(page)
        self.endInsertRows()

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            columns = self.columns()
            if 0 <= section < len(columns):
                return columns[section]['label']
        return None

    def text(self, row, column):
        from trace_app.core import settings
        spec = self.columns()[column]
        value = self.rows[row][1].get(spec['name'])
        text = lava.display(spec, value, self.media)
        if spec.get('type') == 'datetime' and text:
            text = settings.alongside(text)
        return text

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            text = self.text(index.row(), index.column())
            if role == Qt.DisplayRole:
                return ' '.join(text.split())[:300]
            return text if len(text) > 60 else None
        if role == Qt.UserRole and index.column() == 0:
            if self.payload_of is not None:
                return self.payload_of(index.row())
            return self.parent().payload(index.row())
        return None


def row_payload(model, row, source_of=None):
    """A row of `model` (an ArtifactModel) as tags, bookmarks, previews
    and menus take it -- the Modules tab's and the Activity tab's alike."""
    from trace_app.core.case import make_module_ref
    run, artifact = model.run, model.artifact
    rowid, values = model.rows[row]
    media = None
    for column in artifact['columns']:
        if column.get('type') == 'media' and values.get(column['name']):
            media = model.media.get(values[column['name']])
            if media:
                break
    source = None
    if source_of is not None:
        path = (media or {}).get('source_path') or artifact.get('source_path')
        source = source_of(run, path) if path else None
    first = next((model.text(row, column)
                  for column in range(len(artifact['columns']))
                  if model.text(row, column)), '')
    return {
        'is_module_row': True, 'evidence_id': run.get('evidence_id'),
        'artifact_ref': make_module_ref(run['run_id'],
                                        artifact['tablename'], rowid)
        if run.get('run_id') else None,
        'name': f"{artifact['name']}: {first[:80]}",
        'path': f"[{run['tool']}]/{artifact['category']}/"
                f"{artifact['name']}",
        'run_key': run['key'], 'tablename': artifact['tablename'],
        'rowid': rowid, 'source': source,
        'media': dict(media, report=run['report']) if media else None}


class ModulesPanel(QWidget):
    #: (evidence key, tool id) -- the window queues the run.
    run_requested = Signal(object, str)
    manage_requested = Signal()
    row_selected = Signal(dict)
    row_activated = Signal(dict)
    row_menu_requested = Signal(dict, object)
    #: A run (dict) to delete, after the window asks.
    delete_requested = Signal(dict)
    #: Rows shown in the tree and here (runs' artifact rows), for counts.
    count_changed = Signal(int)
    #: (run, artifact, role or None): the examiner sorts an artifact
    #: (core/modules/routes) -- None goes back to TRACE's default.
    route_requested = Signal(dict, dict, object)
    #: (run, artifact, 'activity' | 'timeline'): where its rows went.
    show_requested = Signal(dict, dict, str)
    #: (run, artifact): the examiner adds the whole artifact to the report.
    artifact_report_requested = Signal(dict, dict)
    #: The tab came into view: the window refills its lists.
    shown = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("modulesPanel")
        self.runs = []
        self._targets, self._tools = [], []
        #: (run, staged path) -> source file row; set by the window.
        self.source_of = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # One toolbar, as the Activity tab's: what is shown on the left;
        # the image, the tool and Run, then the run's actions as icons --
        # they were four buttons under the list, taking its room.
        self.toolbar = QToolBar()
        prepare_toolbar(self.toolbar)
        self.status_label = ElidedLabel()
        self.status_label.setObjectName("triageStatus")
        self.status_label.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Preferred)
        self.toolbar.addWidget(self.status_label)
        self.evidence_combo = QComboBox()
        self.evidence_combo.setObjectName("modulesEvidence")
        self.evidence_combo.setToolTip("The image to run the tool on")
        self.evidence_combo.setSizeAdjustPolicy(
            QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.evidence_combo.setMinimumContentsLength(14)
        self.evidence_combo.setMaximumWidth(240)
        self.evidence_combo.currentIndexChanged.connect(self._suggest)
        self.toolbar.addWidget(self.evidence_combo)
        self.tool_combo = QComboBox()
        self.tool_combo.setObjectName("modulesTool")
        self.tool_combo.setToolTip("The tool -- the installed ones, the one "
                                   "for what the image holds first")
        self.tool_combo.setSizeAdjustPolicy(
            QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.tool_combo.setMinimumContentsLength(15)
        self.toolbar.addWidget(self.tool_combo)
        self.run_button = QPushButton("Run")
        self.run_button.setObjectName("triageRunButton")
        icons.apply_to(self.run_button, icons.RUN)
        self.run_button.clicked.connect(self._run)
        self.toolbar.addWidget(self.run_button)
        self.toolbar.addSeparator()
        self.details_action = icons.action(icons.INFO, "Run Details", self)
        self.details_action.setToolTip(
            "What the run read and what the tool found: its input, its "
            "hashes, how many of its artifacts found data, and any errors")
        self.details_action.triggered.connect(self.show_details)
        self.report_action = icons.action(icons.REPORT, "Open HTML Report",
                                          self)
        self.report_action.setToolTip(
            "The tool's own report, in your web browser. It was written by "
            "the tool from the evidence; TRACE shows the same rows here.")
        self.report_action.triggered.connect(self._open_report)
        self.folder_action = icons.action(icons.OPEN_FOLDER,
                                          "Open the Run's Folder", self)
        self.folder_action.triggered.connect(self._open_folder)
        self.delete_action = icons.action(icons.DELETE, "Delete Run", self)
        self.delete_action.triggered.connect(self._delete)
        self.manage_action = icons.action(icons.MODULES,
                                          "External Modules…", self)
        self.manage_action.setToolTip("Install, update or remove tools")
        self.manage_action.triggered.connect(self.manage_requested)
        for action in (self.details_action, self.report_action,
                       self.folder_action, self.delete_action,
                       self.manage_action):
            self.toolbar.addAction(action)
        outer.addWidget(self.toolbar)

        split = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_box = QVBoxLayout(left)
        left_box.setContentsMargins(2, 2, 0, 0)
        left_box.setSpacing(2)
        self.filter_input = QLineEdit()
        self.filter_input.setObjectName("modulesFilter")
        self.filter_input.setPlaceholderText("Filter artifacts…")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.textChanged.connect(self._filter)
        left_box.addWidget(self.filter_input)
        # Exactly what TRACE did not put in Activity (other records and
        # telemetry), so nothing a tool read is hidden by the sorting.
        self.hidden_only = QCheckBox("Only artifacts not in Activity")
        self.hidden_only.setObjectName("modulesHiddenOnly")
        self.hidden_only.setToolTip(
            "Show only the artifacts TRACE did not sort as evidence: they "
            "are read from the tool's database here and in Activity ▸ From "
            "modules, and not copied into the case.")
        self.hidden_only.toggled.connect(
            lambda _on: self._filter(self.filter_input.text()))
        left_box.addWidget(self.hidden_only)
        self.tree = BranchTreeWidget()
        self.tree.setObjectName("modulesRuns")
        self.tree.setHeaderHidden(True)
        self.tree.currentItemChanged.connect(self._chosen)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        left_box.addWidget(self.tree, 1)
        self.tree.setMinimumWidth(180)
        split.addWidget(left)

        self.pages = QStackedWidget()
        self.model = ArtifactModel(self)
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
        self.pages.addWidget(self.table)
        # A run's own page: what it read, what the tool covered. HTML that
        # TRACE writes (every value escaped), shown by QTextBrowser, which
        # fetches nothing.
        self.details = QTextBrowser()
        self.details.setObjectName("modulesDetails")
        self.details.setOpenLinks(False)
        self.pages.addWidget(self.details)
        split.addWidget(self.pages)
        split.setStretchFactor(1, 3)
        split.setSizes([280, 900])
        outer.addWidget(split, 1)
        self._update_buttons()

    def showEvent(self, event):
        super().showEvent(event)
        self.shown.emit()

    # --- the window's side ---------------------------------------------

    def set_targets(self, targets, tools):
        """targets: [(key, label, systems[, icon])] -- icon as the tree
        shows the evidence; tools: [(id, label, suits)] of installed
        tools."""
        self._targets, self._tools = targets, tools
        current = self.evidence_combo.currentData()
        self.evidence_combo.blockSignals(True)
        self.evidence_combo.clear()
        for target in targets:
            key, label = target[0], target[1]
            icon = target[3] if len(target) > 3 else None
            if icon is not None:
                self.evidence_combo.addItem(icon, label, key)
            else:
                self.evidence_combo.addItem(label, key)
            self.evidence_combo.setItemData(
                self.evidence_combo.count() - 1, label, Qt.ToolTipRole)
        index = self.evidence_combo.findData(current)
        self.evidence_combo.setCurrentIndex(max(index, 0))
        self.evidence_combo.blockSignals(False)
        self._suggest()

    def _suggest(self):
        """Only the tools that read what the chosen image holds: iOS ->
        iLEAPP, Android -> aLEAPP (MainWindow._mobile_systems). An Android
        folder is never offered iLEAPP."""
        index = self.evidence_combo.currentIndex()
        systems = set(self._targets[index][2] or ()) \
            if 0 <= index < len(self._targets) else set()
        current = self.tool_combo.currentData()
        self.tool_combo.blockSignals(True)
        self.tool_combo.clear()
        for tool_id, label, suits in self._tools:
            if not suits or set(suits) & systems:
                self.tool_combo.addItem(icons.module_logo(tool_id), label,
                                        tool_id)
        position = self.tool_combo.findData(current)
        self.tool_combo.setCurrentIndex(max(position, 0))
        self.tool_combo.blockSignals(False)
        self._update_buttons()

    def set_runs(self, runs):
        """runs: dicts {'key', 'run_id', 'tool', 'version', 'evidence_id',
        'evidence', 'started', 'status', 'message', 'report', 'folder',
        'manifest', 'input', 'coverage', 'artifacts'}."""
        chosen = self._current()
        self.runs = runs
        self.tree.clear()
        for run_index, run in enumerate(runs):
            rows = sum(a.get('record_count') or 0 for a in run['artifacts'])
            what = (run.get('input') or {}).get('label') or run['evidence']
            head = QTreeWidgetItem([
                f"{run['tool']} {run['version']} — {what}"
                + (f" ({rows:,})" if run['status'] == 'complete'
                   else f" — {run['status']}")])
            head.setIcon(0, icons.module_logo(run['tool']))
            head.setToolTip(0, f"{run['evidence']} · started "
                               f"{run.get('started') or ''}\n"
                               f"{run.get('message') or run['folder']}")
            font = head.font(0)
            font.setBold(True)
            head.setFont(0, font)
            head.setData(0, Qt.UserRole, {'run': run_index})
            self.tree.addTopLevelItem(head)
            groups = {}
            for artifact_index, artifact in enumerate(run['artifacts']):
                groups.setdefault(artifact['category'], []).append(
                    (artifact_index, artifact))
            for category, indexed in groups.items():
                members = [artifact for _index, artifact in indexed]
                count = sum(a.get('record_count') or 0 for a in members)
                group = QTreeWidgetItem([f"{category} ({count:,})"])
                category_icon = icons.leapp_category_icon(members)
                if category_icon is not None:
                    group.setIcon(0, category_icon)
                group.setData(0, Qt.UserRole, {'run': run_index,
                                               'category': category})
                head.addChild(group)
                for artifact_index, artifact in indexed:
                    node = QTreeWidgetItem([
                        f"{artifact['name']} "
                        f"({artifact.get('record_count') or 0:,})"
                        + _ROLE_BADGES.get(artifact.get('role') or '', '')
                        + (' · superseded' if artifact.get('superseded_by')
                           else '')])
                    if artifact.get('route_why'):
                        node.setToolTip(0, _role_tip(artifact))
                    node.setIcon(0, icons.leapp_icon(artifact))
                    node.setData(0, Qt.UserRole,
                                 {'run': run_index,
                                  'artifact': artifact_index})
                    group.addChild(node)
            head.setExpanded(True)
        self.count_changed.emit(sum(
            a.get('record_count') or 0 for run in runs
            for a in run['artifacts']))
        self._filter(self.filter_input.text())
        if not (chosen and self.select(*chosen)):
            self._show_status()
            if not runs:
                self.pages.setCurrentWidget(self.details)
                self.details.setHtml(_EMPTY)
        self._update_buttons()

    def select(self, run_key, tablename=None):
        """Show a run (its details) or one of its artifacts."""
        for index in range(self.tree.topLevelItemCount()):
            head = self.tree.topLevelItem(index)
            if self._item_data(head)['run']['key'] != run_key:
                continue
            if tablename is None:
                self.tree.setCurrentItem(head)
                return True
            for group in range(head.childCount()):
                parent = head.child(group)
                for child in range(parent.childCount()):
                    node = parent.child(child)
                    if self._item_data(node)['artifact'][
                            'tablename'] == tablename:
                        self.tree.setCurrentItem(node)
                        return True
        return False

    def select_row(self, run_key, tablename, rowid):
        """Show one row (from a 'mod:' ref): its artifact chosen, pages
        read until it is there, the row selected."""
        if not self.select(run_key, tablename):
            return False
        while True:
            for position, (found, _values) in enumerate(self.model.rows):
                if found == rowid:
                    index = self.model.index(position, 0)
                    self.table.setCurrentIndex(index)
                    self.table.scrollTo(index)
                    return True
            if not self.model.canFetchMore():
                return False
            self.model.fetchMore()

    def _tree_menu(self, point):
        """Right-click an artifact: how TRACE sorts it, and where its rows
        went."""
        item = self.tree.itemAt(point)
        data = self._item_data(item) if item is not None else None
        if not data or data.get('artifact') is None:
            return
        run, artifact = data['run'], data['artifact']
        menu = QMenu(self)
        role = artifact.get('role') or ''
        for wanted, text in (('evidence', "Treat as Evidence (Activity, "
                                          "Triage, Timeline)"),
                             ('telemetry', "Treat as Telemetry (hidden on "
                                           "the Timeline)"),
                             ('other', "Not Evidence (Timeline only)")):
            action = menu.addAction(text)
            action.setCheckable(True)
            action.setChecked(role == wanted)
            action.triggered.connect(
                lambda _on=False, w=wanted: self.route_requested.emit(
                    run, artifact, w))
        menu.addAction("Use TRACE's Default").triggered.connect(
            lambda: self.route_requested.emit(run, artifact, None))
        menu.addSeparator()
        show = menu.addAction("Show in Activity")
        show.setEnabled(role == 'evidence' and
                        not artifact.get('superseded_by'))
        show.triggered.connect(
            lambda: self.show_requested.emit(run, artifact, 'activity'))
        menu.addAction("Show in Timeline").triggered.connect(
            lambda: self.show_requested.emit(run, artifact, 'timeline'))
        menu.addSeparator()
        menu.addAction(icons.icon(icons.REPORT),
                       "Add Artifact to Report").triggered.connect(
            lambda: self.artifact_report_requested.emit(run, artifact))
        show_menu(menu, self.tree.viewport().mapToGlobal(point))

    def _item_data(self, item):
        """{'run', 'artifact', 'category'} of a tree item. Items keep only
        indices into self.runs: a run dict as item data was converted to a
        Qt map in full -- every artifact and its column map, for each of
        the 637 items of a big iLEAPP run (5 ms each; 4.6 s per redraw,
        redrawn four times while a case opened)."""
        stored = item.data(0, Qt.UserRole) if item is not None else None
        if not stored:
            return None
        run = self.runs[stored['run']]
        artifact = stored.get('artifact')
        return {'run': run, 'category': stored.get('category'),
                'artifact': run['artifacts'][artifact]
                if artifact is not None else None}

    def _current(self):
        item = self.tree.currentItem()
        data = self._item_data(item) if item else None
        if not data:
            return None
        artifact = data.get('artifact')
        return (data['run']['key'], artifact['tablename'] if artifact
                else None)

    def current_run(self):
        item = self.tree.currentItem()
        data = self._item_data(item) if item else None
        return data['run'] if data else None

    # --- what is shown ---------------------------------------------------------

    def _chosen(self, current, _previous):
        data = self._item_data(current) if current else None
        artifact = data.get('artifact') if data else None
        self.model.show(data['run'] if data else None, artifact)
        if artifact is not None:
            self.pages.setCurrentWidget(self.table)
            self.table.resizeColumnsToContents()
            for column in range(self.model.columnCount()):
                if self.table.columnWidth(column) > 360:
                    self.table.setColumnWidth(column, 360)
        elif data is not None:
            self.show_details()
        self._show_status()
        self._update_buttons()

    def _show_status(self):
        run = self.current_run()
        if run is None:
            self.status_label.setText(
                f"{len(self.runs):,} run(s)" if self.runs else
                "No external module has run yet")
            return
        covered = self.coverage(run)
        parts = [f"{run['tool']} {run['version']}", run['evidence']]
        if covered and covered['artifacts']:
            parts.append(f"{covered['with_data']:,} of "
                         f"{covered['artifacts']:,} artifacts found data")
        artifact = self.model.artifact
        if artifact is not None:
            parts.append(f"{artifact['name']}: {self.model.total:,} row(s)")
        self.status_label.setText('  ·  '.join(parts))

    @staticmethod
    def coverage(run):
        """The tool's own account of a run (core/modules/job.coverage),
        kept with the run, or read from its report."""
        if run.get('coverage'):
            return run['coverage']
        try:
            from trace_app.core.modules import job
            run['coverage'] = job.coverage(lava.load(run['report']))
        except Exception:
            run['coverage'] = None
        return run['coverage']

    def show_details(self):
        run = self.current_run()
        if run is None:
            return
        self.pages.setCurrentWidget(self.details)
        self.details.setHtml(details_html(run, self.coverage(run)))

    def _filter(self, text):
        """Artifacts whose name holds `text` (any case); categories with
        none are hidden; runs stay."""
        needle = (text or '').strip().lower()
        hidden_only = self.hidden_only.isChecked()
        for index in range(self.tree.topLevelItemCount()):
            head = self.tree.topLevelItem(index)
            for g in range(head.childCount()):
                group = head.child(g)
                category = group.text(0).lower()
                shown = 0
                for c in range(group.childCount()):
                    node = group.child(c)
                    hit = not needle or needle in node.text(0).lower() \
                        or needle in category
                    if hit and hidden_only:
                        artifact = (self._item_data(node) or {}).get(
                            'artifact') or {}
                        hit = artifact.get('role') != 'evidence' or \
                            bool(artifact.get('superseded_by'))
                    node.setHidden(not hit)
                    shown += hit
                group.setHidden(shown == 0)
                if needle and shown:
                    group.setExpanded(True)

    # --- rows -------------------------------------------------------------

    def payload(self, row):
        """A row as tags, bookmarks, previews and menus take it."""
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

    # --- buttons ------------------------------------------------------------

    def _run(self):
        key = self.evidence_combo.currentData()
        tool = self.tool_combo.currentData()
        if key is not None and tool:
            self.run_requested.emit(key, tool)

    def _open_report(self):
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        run = self.current_run()
        page = os.path.join(run['report'], 'index.html') if run else ''
        if os.path.isfile(page):
            QDesktopServices.openUrl(QUrl.fromLocalFile(page))

    def _open_folder(self):
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        run = self.current_run()
        if run and os.path.isdir(run['folder']):
            QDesktopServices.openUrl(QUrl.fromLocalFile(run['folder']))

    def _delete(self):
        run = self.current_run()
        if run:
            self.delete_requested.emit(run)

    def _update_buttons(self):
        run = self.current_run()
        self.details_action.setEnabled(bool(run))
        self.report_action.setEnabled(bool(run) and os.path.isfile(
            os.path.join(run['report'], 'index.html')))
        self.folder_action.setEnabled(bool(run))
        self.delete_action.setEnabled(bool(run))
        self.run_button.setEnabled(self.evidence_combo.count() > 0 and
                                   self.tool_combo.count() > 0)
        self.run_button.setToolTip(self._why_no_tool())
        self.tool_combo.setToolTip(
            self._why_no_tool() or "The installed tools that read what "
            "the chosen image holds")

    def _why_no_tool(self):
        """'' when a tool can run on the chosen image, else why not."""
        if self.tool_combo.count():
            return ""
        if not self._tools:
            return "Install a tool first: External Modules (the puzzle icon)"
        return ("No installed tool reads this image: iLEAPP needs an iOS "
                "extraction or backup, aLEAPP an Android one")


#: How an artifact was sorted (core/modules/routes), after its name.
_ROLE_BADGES = {'evidence': ' · Activity', 'telemetry': ' · telemetry'}


def _role_tip(artifact):
    role = artifact.get('role') or 'other'
    where = {'evidence': "Its rows are in Activity, Triage and the Timeline",
             'telemetry': "Device telemetry: on the Timeline only when "
                          "Filters ▸ Telemetry from Modules is on",
             'other': "On the Timeline; browse it here"}.get(role, '')
    text = f"{where}.\nSorted by {artifact.get('route_why') or 'TRACE'}."
    if artifact.get('superseded_by'):
        text += ("\nA newer run read the same rows: shown from that run "
                 "instead.")
    return text + "\nRight-click to sort it differently."


_EMPTY = (
    "<h3>External modules</h3>"
    "<p>Parsers by other authors (Alexis Brignoni's LEAPPs) that TRACE "
    "installs on request and runs on evidence:</p>"
    "<ul>"
    "<li><b>iLEAPP</b> &mdash; iPhones and iPads: extractions, iTunes and "
    "Finder backups (encrypted ones with their password)</li>"
    "<li><b>aLEAPP</b> &mdash; Android phones and tablets</li>"
    "<li><b>RLEAPP</b> &mdash; warrant returns from providers (Google, "
    "Snapchat, Synchronoss, Coinbase...)</li>"
    "<li><b>VLEAPP</b> &mdash; vehicles: infotainment and telematics, QNX "
    "head units</li>"
    "<li><b>DLEAPP</b> &mdash; Windows, macOS and Linux computers, and "
    "desktop apps (Discord, Signal, Wire)</li>"
    "</ul>"
    "<p>Install one (the puzzle icon above), choose the image and the "
    "tool, and Run &mdash; TRACE offers the tools that suit the image. It "
    "finds what the tool can read there &mdash; the files its patterns "
    "name, and any phone extraction, backup or return packed in a tar or "
    "zip &mdash; runs it on each, and shows everything it found here."
    "</p>"
    "<p>What is evidence &mdash; calls, messages, contacts, browsing, "
    "places, accounts, apps, Wi-Fi &mdash; joins TRACE's own: the "
    "Activity tab, Triage &#9656; Conversations and Map, the Timeline and "
    "Search, each row saying who read it (<i>Read by</i>). A record TRACE "
    "and the tool both read is one row. Device telemetry (unified logs, "
    "power and health samples, caches) is on the Timeline only when "
    "Filters &#9656; Telemetry from Modules is on. Right-click an artifact "
    "to sort it differently.</p>")


def details_html(run, covered):
    """A run's page: its input, hashes, the tool's coverage, the log's
    problems. Every value from the run escaped."""
    from html import escape as e
    lines = [f"<h3>{e(run['tool'])} {e(run['version'])} — "
             f"{e(run['evidence'])}</h3>"]
    given = run.get('input') or {}
    facts = [("Input", given.get('label') or 'files staged from the image'),
             ("Read from", given.get('path') or ''),
             ("Input SHA-256", given.get('sha256') or ''),
             ("Started (UTC)", _utc(run.get('started'))),
             ("Status", run.get('status') or ''),
             ("Result", run.get('message') or ''),
             ("Folder", run.get('folder') or '')]
    lines.append("<table cellspacing='0' cellpadding='3'>" + ''.join(
        f"<tr><td><b>{e(k)}</b></td><td>{e(str(v))}</td></tr>"
        for k, v in facts if v) + "</table>")
    if covered and covered['artifacts']:
        lines.append(
            f"<h4>What {e(run['tool'])} covered</h4>"
            f"<p>{covered['with_data']:,} of {covered['artifacts']:,} of its "
            f"artifacts found data; {covered['no_files']:,} found none of "
            f"the files they read in this input -- the app or the record "
            f"is not on this phone, or not in what was extracted.</p>")
        if covered['other']:
            lines.append(
                f"<p><b>{len(covered['other']):,} did not finish:</b></p>"
                "<ul>" + ''.join(f"<li>{e(name)}: {e(status)}</li>"
                                 for name, status in covered['other'][:50])
                + "</ul>")
    sorted_rows = accounting_html(run.get('artifacts') or [])
    if sorted_rows:
        lines.append(f"<h4>How TRACE sorted {e(run['tool'])}'s "
                     f"artifacts</h4>" + sorted_rows)
    kept = run.get('not_imported') or []
    if kept:
        lines.append(
            f"<h4>Not added to the Timeline and Search ({len(kept):,})</h4>"
            "<p>Larger than the case's limit (Settings ▸ Analysis ▸ External "
            "tools): their rows stay in the tool's database -- choose the "
            "artifact here to browse them.</p><ul>"
            + ''.join(f"<li>{e(name)}: {count:,} rows</li>"
                      for name, count in kept) + "</ul>")
    problems = log_problems(os.path.join(run['folder'], 'run.log'))
    if problems:
        lines.append(f"<h4>Errors in the tool's log ({len(problems):,})"
                     f"</h4><pre>" + e('\n'.join(problems[:20])) + "</pre>")
    elif os.path.isfile(os.path.join(run['folder'], 'run.log')):
        lines.append("<p>The tool's log records no errors.</p>")
    lines.append("<p>Every artifact the tool has is listed in its log "
                 "(run.log) and its own report, in the run's folder.</p>")
    return ''.join(lines)


_ROLE_NAMES = {'evidence': 'Activity', 'telemetry': 'Telemetry',
               'other': 'Other', 'superseded': 'Superseded by a newer run',
               '': '—'}


def accounting_html(artifacts):
    """The run's accounting (routes.accounting) as a table: how each
    group was sorted, where its rows went, how many; artifacts sorted by
    their name alone are named -- the ones to check."""
    from html import escape as e
    from trace_app.core.modules import routes
    groups = routes.accounting(artifacts)
    if not groups:
        return ''
    body = []
    for group in groups:
        named = ''
        if group['sorted_by'] in ('name', 'columns', 'none') and \
                group['role'] == 'evidence':
            names = group['names'][:30]
            named = ('<br><small>' + e(', '.join(names)) +
                     (' …' if len(group['names']) > 30 else '') +
                     '</small>')
        body.append(
            f"<tr><td>{e(group['words'])}{named}</td>"
            f"<td>{e(_ROLE_NAMES.get(group['role'], group['role']))}</td>"
            f"<td align='right'>{group['artifacts']:,}</td>"
            f"<td align='right'>{group['rows']:,}</td></tr>")
    return ("<table cellspacing='0' cellpadding='3'><tr><th align='left'>"
            "Sorted by</th><th align='left'>Shown in</th><th>Artifacts</th>"
            "<th>Rows</th></tr>" + ''.join(body) + "</table>")


def _utc(text):
    """'2026-10-15T14:12:53+00:00' -> '2026-10-15 14:12:53'."""
    text = (text or '').replace('T', ' ')
    return text[:19] if text.endswith('+00:00') or len(text) > 19 else text


def log_problems(path, limit=200):
    """Lines of a tool's log that report an error (not 'No file found')."""
    out = []
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            for line in handle:
                low = line.lower()
                if ('error' in low or 'traceback' in low or
                        'exception' in low) and 'no error' not in low:
                    out.append(line.rstrip())
                    if len(out) >= limit:
                        break
    except OSError:
        pass
    return out
