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

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHeaderView,
                               QLabel, QPushButton, QSizePolicy,
                               QTableWidget, QToolBar,
                               QTableWidgetItem, QTabWidget, QVBoxLayout,
                               QWidget)

from trace_app.core.case import REPORTED_FINDING_GRADES, REPORTED_MISMATCHES
from trace_app.infra.constants import PANEL_ICON_SIZE, TABLE_ROW_HEIGHT
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui import icons
from trace_app.ui.process_worker import ProcessWorker
from trace_app.ui.viewers.virustotal import verdict_brush
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.row_preview import connect_row_preview
from trace_app.ui.widgets.table_columns import fit_columns
from trace_app.ui.widgets.elided_label import ElidedLabel
from trace_app.ui.widgets.toolbars import prepare_toolbar

logger = logging.getLogger('TRACE.Triage')


#: What each grade means, in the column beside it. The grade names are for the
#: database; this is for the person reading the table.
_WHY = {
    'suspicious': 'Executable disguised as data',
    'notable': 'Unidentifiable and random — likely encrypted',
}


#: Sigma levels, most serious first.
_LEVEL_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3,
                'informational': 4}
#: Event data worth seeing in the Details column of a Sigma detection.
_SIGMA_TELLING = ('CommandLine', 'Image', 'ParentImage', 'ScriptBlockText',
                  'ServiceName', 'ImagePath', 'TargetUserName',
                  'SubjectUserName', 'IpAddress', 'TargetObject',
                  'TargetFilename', 'QueryName', 'DestinationIp',
                  'GrantedAccess', 'Properties', 'ObjectName')

class AnalysisWorker(ProcessWorker):
    """Runs the analysis modules in a child process (core/background.py),
    so the window stays responsive however long the run."""

    progressed = Signal(int, int, str)
    finished_analysis = Signal(int, str)

    kind = 'analysis'

    def __init__(self, image_path, case_folder, evidence_id, modules,
                 parent=None):
        super().__init__({'image_path': image_path,
                          'case_folder': case_folder,
                          'evidence_id': evidence_id,
                          'modules': list(modules)}, parent)

    def on_progress(self, done, total, path):
        self.progressed.emit(done, total, path)

    def on_done(self, count, error):
        self.finished_analysis.emit(count, error)


class TriagePanel(QWidget):
    """The findings, grouped by the reason they are findings."""

    #: Emitted with a row when the examiner lands on it -- a click or an arrow
    #: key -- so the host can show the file without leaving this tab.
    finding_selected = Signal(dict)

    #: Emitted with a row on a double-click: take me to the file's folder.
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
        self._names = {}
        self.icon_resolver = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # The same bar as Listing, Registry and Search: logo, title,
        # then the tab's main action on the right. Without it this tab was the
        # only one in the row that opened straight onto controls.
        self.toolbar = QToolBar()
        prepare_toolbar(self.toolbar)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        icon_label = QLabel()
        icon_label.setObjectName("panelIcon")
        icons.apply_pixmap(icon_label, icons.TRIAGE, PANEL_ICON_SIZE)
        self.toolbar.addWidget(icon_label)
        title = QLabel("Triage")
        title.setObjectName("panelTitle")
        self.toolbar.addWidget(title)

        # The state of the analysis, after the title and before the button
        # that runs it, so the bar reads as one sentence.
        self.status_label = ElidedLabel()
        self.status_label.setObjectName("triageStatus")
        self.status_label.setWordWrap(False)
        self.status_label.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Preferred)
        self.toolbar.addWidget(self.status_label)

        # One case is one investigation across every device in it, so the
        # findings are the whole case's by default; this narrows them to one
        # image when that is the question.
        self.evidence_filter = QComboBox()
        self.evidence_filter.setObjectName("triageEvidenceFilter")
        self.evidence_filter.setToolTip("Show findings from every image in "
                                        "the case, or from one.")
        self.evidence_filter.currentIndexChanged.connect(self._filter_changed)
        self.toolbar.addWidget(self.evidence_filter)

        self.run_button = QPushButton("Run Analysis")
        self.run_button.setObjectName("triageRunButton")
        self.run_button.clicked.connect(self.run_requested.emit)
        self.toolbar.addWidget(self.run_button)
        outer.addWidget(self.toolbar)

        layout = QVBoxLayout()
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(4)
        outer.addLayout(layout)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("triageTabs")
        self.tabs.setDocumentMode(True)
        # No base line: in document mode Qt rules one along the top of the
        # tab row, a stray line no other tab strip in TRACE has.
        self.tabs.tabBar().setDrawBase(False)
        layout.addWidget(self.tabs, 1)

        self.mismatch_table = self._make_table(
            ['Name', 'Claims to be', 'Actually is', 'Why', 'Size', 'Path'])
        self.tabs.addTab(self.mismatch_table, icons.icon(icons.FINDING_MISMATCH),
                         "Type mismatches")

        self.entropy_table = self._make_table(
            ['Name', 'Entropy', 'Peak', 'Type', 'Size', 'Path'])
        self.tabs.addTab(self.entropy_table, icons.icon(icons.FINDING_ENTROPY),
                         "High entropy")

        self.duplicate_table = self._make_table(
            ['Name', 'Copies', 'Size', 'Wasted', 'SHA-256', 'Path'])
        self.tabs.addTab(self.duplicate_table,
                         icons.icon(icons.FINDING_DUPLICATES), "Duplicates")

        self.hidden_table = self._make_table(
            ['Name', 'Severity', 'Finding', 'Size', 'Path'])
        self.tabs.addTab(self.hidden_table, icons.icon(icons.FINDING_HIDDEN),
                         "Hidden data")

        self.photo_table = self._make_table(
            ['Name', 'Taken', 'Camera', 'Location', 'Software', 'Path'])
        self.tabs.addTab(self.photo_table, icons.icon(icons.FINDING_PHOTO),
                         "Photos")

        self.author_table = self._make_table(
            ['Name', 'Author', 'Last saved by', 'Company', 'Application',
             'Created', 'Modified', 'Path'])
        self.tabs.addTab(self.author_table, icons.icon(icons.FINDING_AUTHOR),
                         "Authors")

        self.yara_table = self._make_table(
            ['Name', 'Rule', 'Rule set', 'Severity', 'Matched', 'Path'])
        self.tabs.addTab(self.yara_table, icons.icon(icons.FINDING_YARA),
                         "YARA")

        self.executable_table = self._make_table(
            ['Name', 'Severity', 'Kind', 'Architecture', 'Linked', 'Signed',
             'Indicators', 'Path'])
        self.tabs.addTab(self.executable_table, icons.icon(icons.EXECUTABLE),
                         "Executables")

        self.sigma_table = self._make_table(
            ['Log', 'Level', 'Rule', 'Time (UTC)', 'Event', 'Computer',
             'ATT&CK', 'Details', 'Path'])
        self.tabs.addTab(self.sigma_table, icons.icon(icons.SIGMA), "Sigma")

        #: Widest each free-text column may grow; the full text is in the
        #: cell's tooltip. Uncapped, one long finding or an eight-author paper
        #: pushed every column after it off the screen.
        self._column_caps = {
            id(self.hidden_table): {3: 520},
            id(self.photo_table): {3: 220, 5: 200},
            id(self.author_table): {2: 260, 3: 180, 4: 180, 5: 220},
            id(self.yara_table): {2: 220, 5: 420},
            id(self.executable_table): {6: 240, 7: 420},
            id(self.sigma_table): {3: 320, 7: 180, 8: 420, 9: 320},
        }

        #: Sub-tab index by the name the tree uses for it. The bookmarks tab
        #: is added by the host (add_bookmarks_tab), since its panel is shared.
        self._tab_for = {'mismatch': 0, 'entropy': 1, 'duplicates': 2,
                         'hidden': 3, 'photos': 4, 'authors': 5, 'yara': 6,
                         'executables': 7, 'sigma': 8}

        self.refresh()

    def _make_table(self, headers):
        # Every finding says which image it came from, second after its name:
        # with several devices in a case, a file name alone is not a location.
        headers = [headers[0], 'Evidence'] + list(headers[1:])
        table = QTableWidget()
        table.setObjectName("triageTable")
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(TABLE_ROW_HEIGHT)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # Paints the severity colours, which the theme's item colour would
        # otherwise override.
        table.setItemDelegate(NoFocusDelegate(table))
        table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        table.itemDoubleClicked.connect(self._activate)
        connect_row_preview(table, self.finding_selected.emit)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(
            lambda point, t=table: self._context_menu(t, point))
        return table

    def add_carved_tab(self, panel):
        """Make carving a sub-tab here (ui/viewers/carved_panel.py).

        Recovered files are findings like any other: one place to review
        them, following the same image filter. Added by the host, which
        owns the jobs that carve.
        """
        self._carved_panel = panel
        self._tab_for['carved'] = self.tabs.addTab(
            panel, icons.icon(icons.FINDING_CARVED), "Carved files")
        panel.count_changed.connect(self._set_carved_count)
        panel.case = self.case
        panel.set_evidence_filter(self.evidence_id)

    def add_indicators_tab(self, panel):
        """Make the case's indicators a sub-tab here
        (ui/viewers/indicators_panel.py), following the same image filter."""
        self._indicators_panel = panel
        self._tab_for['indicators'] = self.tabs.addTab(
            panel, icons.icon(icons.FINDING_INDICATORS), "Indicators")
        panel.count_changed.connect(self._set_indicator_count)
        panel.set_case(self.case)
        panel.set_evidence_filter(self.evidence_id)

    def add_ntfs_tab(self, panel):
        """NTFS internals (ui/viewers/ntfs_panel.py): timestomping, streams
        and downloads, the change journal -- same image filter."""
        self._ntfs_panel = panel
        self._tab_for['ntfs'] = self.tabs.addTab(
            panel, icons.icon(icons.NTFS), "NTFS")
        panel.count_changed.connect(self._set_ntfs_count)
        panel.evidence_id = self.evidence_id
        panel.set_case(self.case)

    def add_persistence_tab(self, panel):
        """Autostarts (ui/viewers/persistence_panel.py), same image
        filter."""
        self._persistence_panel = panel
        self._tab_for['persistence'] = self.tabs.addTab(
            panel, icons.icon(icons.PERSISTENCE), "Persistence")
        panel.count_changed.connect(
            lambda count: self.tabs.setTabText(
                self._tab_for['persistence'], f"Persistence ({count:,})"))
        panel.evidence_id = self.evidence_id
        panel.set_case(self.case)

    def add_deleted_tab(self, panel):
        """Deleted files and what is left of each
        (ui/viewers/deleted_panel.py), following the same image filter."""
        self._deleted_panel = panel
        self._tab_for['deleted'] = self.tabs.addTab(
            panel, icons.icon(icons.DELETED_FILES), "Deleted files")
        panel.count_changed.connect(
            lambda count: self.tabs.setTabText(
                self._tab_for['deleted'], f"Deleted files ({count:,})"))
        panel.evidence_id = self.evidence_id
        panel.set_case(self.case)

    def add_map_tab(self, panel):
        """Located evidence on a map (ui/viewers/map_panel.py), following
        the same image filter."""
        self._map_panel = panel
        self._tab_for['map'] = self.tabs.addTab(
            panel, icons.icon(icons.FINDING_LOCATION), "Map")
        panel.count_changed.connect(
            lambda count: self.tabs.setTabText(
                self._tab_for['map'], f"Map ({count:,})"))
        panel.evidence_id = self.evidence_id
        panel.set_case(self.case)

    def add_thumbnails_tab(self, panel):
        """Pictures in thumbnail caches (ui/viewers/thumbnails_panel.py),
        following the same image filter."""
        self._thumbnails_panel = panel
        self._tab_for['thumbnails'] = self.tabs.addTab(
            panel, icons.icon(icons.THUMBNAILS), "Thumbnails")
        panel.count_changed.connect(
            lambda count: self.tabs.setTabText(
                self._tab_for['thumbnails'], f"Thumbnails ({count:,})"))
        panel.evidence_id = self.evidence_id
        panel.set_case(self.case)

    def add_keywords_tab(self, panel):
        """Keyword-list hits (ui/viewers/keywords_panel.py), following the
        same image filter."""
        self._keywords_panel = panel
        self._tab_for['keywords'] = self.tabs.addTab(
            panel, icons.icon(icons.KEYWORDS), "Keywords")
        panel.count_changed.connect(
            lambda count: self.tabs.setTabText(
                self._tab_for['keywords'], f"Keywords ({count:,})"))
        panel.evidence_id = self.evidence_id
        panel.set_case(self.case)

    def add_similar_tab(self, panel):
        """Pictures that look alike (ui/viewers/similar_pictures_panel.py),
        following the same image filter."""
        self._similar_panel = panel
        self._tab_for['similar'] = self.tabs.addTab(
            panel, icons.icon(icons.FINDING_DUPLICATES), "Similar pictures")
        panel.count_changed.connect(
            lambda count: self.tabs.setTabText(
                self._tab_for['similar'], f"Similar pictures ({count:,})"))
        panel.evidence_id = self.evidence_id
        panel.set_case(self.case)

    def add_hash_tab(self, panel):
        """Hash-set matches (ui/viewers/hash_matches_panel.py), following
        the same image filter."""
        self._hash_panel = panel
        self._tab_for['hashes'] = self.tabs.addTab(
            panel, icons.icon(icons.HASH_SETS), "Hash sets")
        panel.count_changed.connect(self._set_hash_count)
        panel.evidence_id = self.evidence_id
        panel.set_case(self.case)

    def _set_hash_count(self, count):
        index = self._tab_for.get('hashes')
        if index is not None:
            self.tabs.setTabText(index, f"Hash sets ({count:,})")

    def _set_ntfs_count(self, count):
        index = self._tab_for.get('ntfs')
        if index is not None:
            self.tabs.setTabText(index, f"NTFS ({count:,})")

    def _set_indicator_count(self, count):
        index = self._tab_for.get('indicators')
        if index is not None:
            self.tabs.setTabText(index, f"Indicators ({count:,})")

    def _set_carved_count(self, count):
        index = self._tab_for.get('carved')
        if index is not None:
            self.tabs.setTabText(index, f"Carved files ({count})")

    def add_bookmarks_tab(self, panel):
        """Make the case's bookmarks a sub-tab here.

        Findings and bookmarks are the two lists an examiner works down, and
        having both in one tab means reviewing them is one place rather than a
        tab and a dock that was hidden by default.
        """
        self._bookmarks_panel = panel
        self._tab_for['bookmarks'] = self.tabs.addTab(
            panel, icons.icon(icons.BOOKMARK), "Bookmarks")
        panel.count_changed.connect(self._set_bookmark_count)
        self._set_bookmark_count(panel.count)

    def _set_bookmark_count(self, count):
        index = self._tab_for.get('bookmarks')
        if index is not None:
            self.tabs.setTabText(index, f"Bookmarks ({count})")

    def show_group(self, name):
        """Bring a sub-tab forward by name: 'mismatch', 'entropy',
        'duplicates', 'hidden', 'photos', 'authors', 'carved', 'indicators'
        or 'bookmarks'; 'ntfs:timestomp', 'ntfs:streams' or 'ntfs:journal'
        for a section of the NTFS tab. Unknown names leave the current one."""
        if name and name.startswith('hash'):
            name = 'hashes'
        if name and name.startswith('ntfs'):
            panel = getattr(self, '_ntfs_panel', None)
            if panel is not None and ':' in name:
                panel.show_section(name.split(':', 1)[1])
            name = 'ntfs'
        index = self._tab_for.get(name)
        if index is not None:
            self.tabs.setCurrentIndex(index)

    def set_case(self, case, evidence_id=None):
        """Show `case`. `evidence_id` narrows to one image; None keeps the
        examiner's own choice in the filter (all evidence by default)."""
        self.case = case
        self._names = {}
        if case is not None:
            self._names = {r['id']: r.get('display_name')
                           or r['path'].replace('\\', '/').rsplit('/', 1)[-1]
                           for r in case.evidence()}
        keep = evidence_id if evidence_id is not None else self.evidence_id
        self._fill_filter(keep if keep in self._names else None)
        self.refresh()
        carved = getattr(self, '_carved_panel', None)
        if carved is not None:
            carved.case = case
            carved.set_evidence_filter(self.evidence_id)
        indicators = getattr(self, '_indicators_panel', None)
        if indicators is not None:
            indicators.evidence_id = self.evidence_id
            indicators.set_case(case)
        for extra in self._extra_panels():
            if extra is not None:
                extra.evidence_id = self.evidence_id
                extra.set_case(case)

    def set_evidence_filter(self, evidence_id):
        """Narrow to one image, or None for the whole case."""
        index = self.evidence_filter.findData(evidence_id)
        self.evidence_filter.setCurrentIndex(index if index >= 0 else 0)

    def _fill_filter(self, selected):
        self.evidence_filter.blockSignals(True)
        self.evidence_filter.clear()
        self.evidence_filter.addItem("All evidence", None)
        for evidence_id, name in sorted(self._names.items(),
                                        key=lambda kv: kv[1].lower()):
            self.evidence_filter.addItem(name, evidence_id)
        index = self.evidence_filter.findData(selected)
        self.evidence_filter.setCurrentIndex(index if index >= 0 else 0)
        self.evidence_filter.blockSignals(False)
        self.evidence_id = self.evidence_filter.currentData()
        # One image needs no choosing.
        self.evidence_filter.setVisible(len(self._names) > 1)

    def _filter_changed(self, _index):
        self.evidence_id = self.evidence_filter.currentData()
        if self.case is not None:
            self.refresh()
        carved = getattr(self, '_carved_panel', None)
        if carved is not None:
            carved.set_evidence_filter(self.evidence_id)
        indicators = getattr(self, '_indicators_panel', None)
        if indicators is not None:
            indicators.set_evidence_filter(self.evidence_id)
        for extra in self._extra_panels():
            if extra is not None:
                extra.set_evidence_filter(self.evidence_id)

    def _extra_panels(self):
        return (getattr(self, '_ntfs_panel', None),
                getattr(self, '_hash_panel', None),
                getattr(self, '_persistence_panel', None),
                getattr(self, '_keywords_panel', None),
                getattr(self, '_thumbnails_panel', None),
                getattr(self, '_deleted_panel', None),
                getattr(self, '_map_panel', None),
                getattr(self, '_similar_panel', None))

    def refresh(self):
        """Redraw from what the case holds now."""
        if self.case is None:
            self.status_label.setText(
                "Analysis findings are kept in a case. File ▸ New Case "
                "starts one.")
            self.run_button.setEnabled(False)
            for table in self._finding_tables():
                table.setRowCount(0)
            self._set_counts({})
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
                    "for its true type, entropy, hash, hidden data and "
                    "metadata, and indexes it for search and indicators.")
        else:
            images = len(self._names)
            scope = (f" across {images} images" if self.evidence_id is None
                     and images > 1 else '')
            self.status_label.setText(
                f"{summary['analysed']:,} file(s) analysed{scope}")

        self._fill_mismatches()
        self._fill_entropy()
        self._fill_duplicates()
        self._fill_hidden()
        self._fill_photos()
        self._fill_authors()
        self._fill_yara()
        self._fill_executables()
        self._fill_sigma()
        self._set_counts(summary)

    def _finding_tables(self):
        return (self.mismatch_table, self.entropy_table, self.duplicate_table,
                self.hidden_table, self.photo_table, self.author_table,
                self.yara_table, self.executable_table, self.sigma_table)

    def _fill_hidden(self):
        rows = self.case.findings(self.evidence_id, 'hidden',
                                  grades=REPORTED_FINDING_GRADES)
        table = self.hidden_table
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            values = [
                row.get('name') or '',
                (row.get('grade') or '').capitalize(),
                row.get('summary') or '',
                FileSystemUtils.get_readable_size(row.get('size') or 0),
                row.get('path') or '',
            ]
            self._fill_row(table, position, values, row)
            # Severity in its colour: suspicious red, notable amber.
            state = ('malicious' if row.get('grade') == 'suspicious'
                     else 'suspicious')
            for column in (2, 3):
                table.item(position, column).setForeground(
                    verdict_brush(state))
                table.item(position, column).setToolTip(
                    row.get('summary') or '')

    def _fill_photos(self):
        rows = self.case.findings(self.evidence_id, 'photo')
        table = self.photo_table
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            facts = row.get('detail') or {}
            camera = ' '.join(p for p in (facts.get('make'),
                                          facts.get('model')) if p)
            location = (f"{facts['latitude']:.5f}, {facts['longitude']:.5f}"
                        if 'latitude' in facts else '')
            values = [
                row.get('name') or '',
                facts.get('taken') or facts.get('modified') or '',
                camera,
                location,
                facts.get('software') or '',
                row.get('path') or '',
            ]
            self._fill_row(table, position, values, row)
            if location:
                # A position is the finding here; it is what an examiner
                # scans the column for.
                table.item(position, 4).setForeground(
                    verdict_brush('suspicious'))

    def _fill_authors(self):
        rows = self.case.findings(self.evidence_id, 'authors')
        table = self.author_table
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            facts = row.get('detail') or {}
            values = [
                row.get('name') or '',
                facts.get('author') or '',
                facts.get('last_saved_by') or '',
                facts.get('company') or '',
                facts.get('application') or facts.get('producer') or '',
                facts.get('created') or '',
                facts.get('modified') or '',
                row.get('path') or '',
            ]
            self._fill_row(table, position, values, row)

    def _fill_yara(self):
        rows = self.case.findings(self.evidence_id, 'yara', limit=20000)
        self._yara_count = len({(r['evidence_id'], r['artifact_ref'])
                                for r in rows})
        table = self.yara_table
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            facts = row.get('detail') or {}
            strings = facts.get('strings') or []
            matched = ', '.join(dict.fromkeys(
                f"{s['identifier']} \u201c{s['data'][:40]}\u201d"
                for s in strings[:4]))
            values = [row.get('name') or '', facts.get('rule') or row['kind'],
                      facts.get('set') or '',
                      (row.get('grade') or '').capitalize(), matched,
                      row.get('path') or '']
            self._fill_row(table, position, values, row)
            tone = 'malicious' if row.get('grade') == 'suspicious' \
                else 'suspicious'
            table.item(position, 4).setForeground(verdict_brush(tone))
            tip = [f"Rule {facts.get('rule')} ({facts.get('set')})"]
            if facts.get('tags'):
                tip.append("Tags: " + ', '.join(facts['tags']))
            tip += [f"{k}: {v}" for k, v in (facts.get('meta') or {}).items()]
            tip += [f"{s['identifier']} at {s['offset']:,}: {s['data']}"
                    for s in strings[:20]]
            for column in range(table.columnCount()):
                table.item(position, column).setToolTip('\n'.join(tip))

    def _fill_executables(self):
        """Every PE, ELF and Mach-O file, those with something worth a
        look first (core/executables.py)."""
        rows = self.case.findings(self.evidence_id, 'executables',
                                  limit=50000)
        table = self.executable_table
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            facts = row.get('detail') or {}
            signed = facts.get('signed')
            flags = facts.get('indicators') or []
            values = [
                row.get('name') or '',
                (row.get('grade') or '').capitalize()
                if flags else '',
                ' '.join(p for p in (facts.get('format'), facts.get('kind'))
                         if p),
                facts.get('architecture') or '',
                facts.get('compiled') or facts.get('compiled_note') or '',
                ('Yes' + (f", {signed}" if signed else '')
                 if signed is not None else
                 ('' if (facts.get('format') or '').startswith('ELF')
                  else 'No')),
                '; '.join(f['text'] for f in flags),
                row.get('path') or '',
            ]
            self._fill_row(table, position, values, row)
            if flags:
                tone = ('malicious' if row.get('grade') == 'suspicious'
                        else 'suspicious')
                for column in (2, 7):
                    table.item(position, column).setForeground(
                        verdict_brush(tone))
            table.item(position, 7).setToolTip(row.get('summary') or '')

    def _fill_sigma(self):
        """Every event a Sigma rule matched, most serious first."""
        rows = self.case.findings(self.evidence_id, 'sigma', limit=50000)
        rows.sort(key=lambda r: (_LEVEL_ORDER.get(
            (r.get('detail') or {}).get('level'), 5),
            (r.get('detail') or {}).get('time') or ''))
        self._sigma_count = len(rows)
        table = self.sigma_table
        table.setRowCount(len(rows))
        for position, row in enumerate(rows):
            facts = row.get('detail') or {}
            data = facts.get('data') or {}
            telling = [f"{k}: {v}" for k, v in data.items()
                       if k in _SIGMA_TELLING and v][:3]
            values = [
                row.get('name') or '',
                (facts.get('level') or '').capitalize(),
                facts.get('rule') or '',
                (facts.get('time') or '')[:23],
                str(facts.get('event_id') or ''),
                facts.get('computer') or '',
                ', '.join(facts.get('attack') or []),
                '; '.join(telling),
                row.get('path') or '',
            ]
            self._fill_row(table, position, values, row)
            if row.get('grade') in ('suspicious', 'notable'):
                tone = 'malicious' if row['grade'] == 'suspicious' \
                    else 'suspicious'
                for column in (2, 3):
                    table.item(position, column).setForeground(
                        verdict_brush(tone))
            tip = [facts.get('rule') or '', facts.get('description') or '']
            if facts.get('falsepositives'):
                tip.append("False positives: "
                           + '; '.join(facts['falsepositives']))
            tip += [f"{k}: {v}" for k, v in list(data.items())[:25]]
            for column in range(table.columnCount()):
                table.item(position, column).setToolTip(
                    '\n'.join(t for t in tip if t)[:4000])

    def _set_counts(self, summary):
        # The count belongs on the tab, so it is readable whichever tab is
        # open -- an examiner should be able to see there are findings without
        # clicking through every one.
        labels = (('mismatch', "Type mismatches", 'mismatches'),
                  ('entropy', "High entropy", 'high_entropy'),
                  ('duplicates', "Duplicates", 'duplicate_groups'),
                  ('hidden', "Hidden data", 'hidden'),
                  ('photos', "Photos", 'photos'),
                  ('authors', "Authors", 'authors'),
                  ('executables', "Executables", 'executables'))
        for key, label, field in labels:
            self.tabs.setTabText(self._tab_for[key],
                                 f"{label} ({summary.get(field, 0)})")
        self.tabs.setTabText(self._tab_for['yara'],
                             f"YARA ({getattr(self, '_yara_count', 0)})")
        self.tabs.setTabText(self._tab_for['sigma'],
                             f"Sigma ({getattr(self, '_sigma_count', 0)})")

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
        values = [values[0], self._names.get(payload.get('evidence_id'), '')] \
            + list(values[1:])
        for column, value in enumerate(values):
            cell = QTableWidgetItem(str(value))
            if column != 0 and value:
                cell.setToolTip(str(value))
            if column == 0:
                cell.setData(Qt.UserRole, payload)
                icon = self._icon_for(payload.get('name') or '')
                if icon is not None:
                    cell.setIcon(icon)
                cell.setToolTip(payload.get('path') or '')
            table.setItem(position, column, cell)
        if position == table.rowCount() - 1:
            caps = {table.columnCount() - 1: 260}
            caps.update(self._column_caps.get(id(table), {}))
            fit_columns(table, caps)
            # Room for the file icon as well as the name: fitted to the text
            # alone, a short name like "mum.jpg" was elided to "mu…".
            table.setColumnWidth(0, max(table.columnWidth(0), 160))

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
