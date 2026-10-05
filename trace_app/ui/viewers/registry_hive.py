import io
import logging

from PySide6.QtCore import QSize, Qt, QThread, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QTextEdit, QToolBar, QLabel, \
    QSplitter, QTableWidget, QTableWidgetItem, QComboBox, QSizePolicy, QPushButton, QMenu, QApplication, QHeaderView
from Registry import Registry
from Registry.Registry import RegistryValue, RegistryKey
from trace_app.infra.paths import resource_path
from trace_app.infra.constants import (PANEL_ICON_SIZE, SPLITTER_HANDLE_WIDTH,
                                       TREE_ICON_SIZE, TREE_INDENTATION)
from trace_app.ui import icons
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.tree_branch import BranchTreeWidget
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar
from trace_app.ui.widgets.property_table import PropertyTable

logger = logging.getLogger('TRACE.Registry')



def _own_handler(path, unlocks):
    """The evidence opened afresh for one thread, with the volumes the
    examiner unlocked unlocked again. The window's own handler is never
    used here: the window reads it at the same time (opening the image,
    building its tree), and one image's volume objects used from two
    threads returned wrong bytes and crashed on Linux and macOS."""
    from trace_app.core.background import _open_image
    return _open_image(path, unlocks)


class _HiveFinder(QThread):
    """Finds the hives on each piece of evidence in turn
    (core/registry_hives.py), off the UI thread: the Evidence list then says
    which images hold a registry at all."""

    #: (evidence path, [Hive]).
    found = Signal(str, object)

    def __init__(self, evidence, parent=None):
        super().__init__(parent)
        self.evidence = evidence            # [(path, unlocks)]

    def run(self):
        from trace_app.core import registry_hives
        for path, unlocks in self.evidence:
            if self.isInterruptionRequested():
                return
            handler = None
            try:
                handler = _own_handler(path, unlocks)
                hives = registry_hives.find_hives(
                    handler, self.isInterruptionRequested)
            except Exception as exc:
                logger.error("Could not look for hives in %s: %s", path, exc)
                hives = []
            finally:
                if handler is not None:
                    handler.close_resources()
            if not self.isInterruptionRequested():
                self.found.emit(path, hives)


class _HiveLoader(QThread):
    """Reads one hive out of the evidence, off the UI thread, in memory with
    its transaction logs applied; the tree is built on the UI thread."""

    #: (parsed root key, recovery facts) on success.
    loaded = Signal(object, object)
    failed = Signal(str)

    def __init__(self, path, unlocks, hive, parent=None):
        super().__init__(parent)
        self.path = path
        self.unlocks = unlocks
        self.hive = hive

    def run(self):
        from trace_app.core import registry_hives
        handler = None
        try:
            handler = _own_handler(self.path, self.unlocks)
            data, facts = registry_hives.read_hive(handler, self.hive)
            root = Registry.Registry(io.BytesIO(data)).root()
            if not self.isInterruptionRequested():
                self.loaded.emit(root, facts)
        except Exception as exc:
            logger.error("Could not read %s: %s", self.hive.path, exc)
            self.failed.emit(f"Could not read {self.hive.label}: {exc}")
        finally:
            if handler is not None:
                handler.close_resources()


class RegistryExtractor(QWidget):
    """The Registry tab: pick a piece of evidence, then one of the hives
    found on it -- system, per user, Amcache, RegBack copies -- and browse
    it. It reads the evidence chosen here, never whichever image happens
    to be active elsewhere in the window."""

    #: Progress text for the window's status bar. Emitted rather than written
    #: directly, so this widget stays independent of the window it sits in.
    statusMessage = Signal(str)

    #: Item data slot recording whether a node's children have been built.
    POPULATED_ROLE = Qt.UserRole + 1

    def __init__(self, image_handler=None):
        super().__init__()
        #: [(path, display name, handler)] -- the evidence open in the window.
        self._evidence = []
        #: {path: [Hive]} once searched.
        self._hives = {}
        #: The path the examiner picked; None until they pick one.
        self._chosen = None
        self._finder = None
        #: The running hive reader, retained so it is not collected mid-read.
        self._loader = None
        #: (path, Hive) of what the tree shows.
        self.shown = None
        self._source_rows = []
        #: path -> {volume key: secret} the examiner unlocked; set by the
        #: window, so this tab's threads can unlock their own copies.
        self.unlocks_for = lambda path: {}
        #: path -> which volumes were unlocked when it was searched.
        self._searched_unlocked = {}
        self.init_ui()

    def set_image_handler(self, image_handler):
        """Kept for callers of the old interface: the browser follows its
        own Evidence choice, not the window's active image."""

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setLayout(main_layout)

        self.toolbar = QToolBar("Toolbar")

        prepare_toolbar(self.toolbar)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.toolbar)

        self.icon_label = QLabel()
        self.icon_label.setObjectName("panelIcon")
        icons.apply_pixmap(self.icon_label, icons.REGISTRY, PANEL_ICON_SIZE)
        self.toolbar.addWidget(self.icon_label)

        self.label = QLabel("Registry Browser")
        self.label.setObjectName("panelTitle")
        self.toolbar.addWidget(self.label)

        spacer = QLabel()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        self.evidenceSelector = QComboBox()
        self.evidenceSelector.setToolTip("The evidence to read hives from")
        self.evidenceSelector.setSizeAdjustPolicy(
            QComboBox.AdjustToContents)
        self.evidenceSelector.activated.connect(self._evidence_picked)
        self.toolbar.addWidget(self.evidenceSelector)

        self.hiveSelector = QComboBox()
        self.hiveSelector.setToolTip("The hives found on that evidence")
        self.hiveSelector.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.hiveSelector.setMinimumContentsLength(24)
        self.toolbar.addWidget(self.hiveSelector)

        self.loadHiveButton = QPushButton("Load")
        self.loadHiveButton.clicked.connect(self.load_selected_hive)
        self.toolbar.addWidget(self.loadHiveButton)

        # Splitter setup
        self.splitter = QSplitter(Qt.Horizontal)
        # A hairline between panes. QSplitter reserves handleWidth regardless
        # of what the stylesheet paints, and the default 7px showed as a thick
        # grey band; the drag area stays usable because Qt widens the hit
        # region past the painted rule.
        self.splitter.setHandleWidth(SPLITTER_HANDLE_WIDTH)
        main_layout.addWidget(self.splitter)

        # Tree Widget Setup. The same class and treatment as the evidence tree
        # in the main window: expand arrows painted rather than taken from a
        # stylesheet image (Qt rasterises those without antialiasing), no
        # dotted focus rectangle, and an explicit icon size so a 24px glyph is
        # not squeezed into whatever the platform style happens to pick.
        self.treeWidget = BranchTreeWidget()
        self.treeWidget.header().hide()
        self.treeWidget.setIconSize(QSize(TREE_ICON_SIZE, TREE_ICON_SIZE))
        self.treeWidget.setIndentation(TREE_INDENTATION)
        self.treeWidget.setFrameShape(BranchTreeWidget.NoFrame)
        self.treeWidget.setItemDelegate(NoFocusDelegate(self.treeWidget))
        self.splitter.addWidget(self.treeWidget)

        # Details Panel and Table Setup
        self.detailsSplitter = QSplitter(Qt.Vertical)
        self.detailsSplitter.setHandleWidth(SPLITTER_HANDLE_WIDTH)
        self.splitter.addWidget(self.detailsSplitter)

        # Key metadata. A table rather than generated HTML, so it matches the
        # values table below it and follows the application theme.
        self.metadataPanel = PropertyTable("Field", "Value")
        self.detailsSplitter.addWidget(self.metadataPanel)

        # Table Setup for displaying values
        self.tableWidget = QTableWidget()
        self.tableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tableWidget.setSelectionBehavior(QTableWidget.SelectRows)
        self.tableWidget.verticalHeader().setVisible(False)
        self.detailsSplitter.addWidget(self.tableWidget)

        # Adjust proportions
        self.splitter.setSizes([300, 700])  # Allocate space for the tree and details
        self.detailsSplitter.setStretchFactor(0, 1)  # Metadata panel
        self.detailsSplitter.setStretchFactor(1, 1)  # Table panel

        # Connect the click event
        self.treeWidget.itemClicked.connect(self.on_item_clicked)
        self.treeWidget.itemExpanded.connect(self._on_item_expanded)
        # Every control in this toolbar gets the shared height, once it is built.
        align_controls(self.toolbar)
        self._fill_evidence()

    def onCustomContextMenuRequested(self, position):
        # Create the context menu
        contextMenu = QMenu(self)
        copyAction = contextMenu.addAction("Copy")

        # Execute the menu and check which action was triggered
        action = contextMenu.exec_(self.tableWidget.mapToGlobal(position))

        if action == copyAction:
            # Copy the selected cell's text to the clipboard
            selectedIndexes = self.tableWidget.selectedIndexes()
            if selectedIndexes:
                selectedText = selectedIndexes[0].data()  # Assuming single selection for simplicity
                QApplication.clipboard().setText(selectedText)

    # --- which evidence, which hive ------------------------------------------

    def set_evidence(self, evidence):
        """The evidence open in the window: [(path, display name,
        handler)]. Hives are looked for on any not searched yet."""
        unlocked = {p: sorted(self.unlocks_for(p)) for p, _n, _h in evidence}
        if [(p, n, id(h)) for p, n, h in evidence] == \
                [(p, n, id(h)) for p, n, h in self._evidence] and \
                all(self._searched_unlocked.get(p) == keys
                    for p, keys in unlocked.items() if p in self._hives):
            return                  # every click activates an image
        known = {path for path, _n, _h in evidence}
        handlers = {path: handler for path, _n, handler in evidence}
        old = {path: handler for path, _n, handler in self._evidence}
        # Gone, reopened under the same path, or a volume unlocked since it
        # was searched: forget what was found.
        for path in list(self._hives):
            if path not in known or old.get(path) is not handlers.get(path) \
                    or self._searched_unlocked.get(path) != unlocked[path]:
                self._hives.pop(path, None)
        self._evidence = list(evidence)
        if self._chosen not in known:
            self._chosen = None
        if self.shown and self.shown[0] not in self._hives:
            self.clear()
        self._fill_evidence()
        self._search()

    def _search(self):
        if self._finder is not None and self._finder.isRunning():
            self._finder.requestInterruption()
            self._finder.wait(10000)
        pending = [(path, self.unlocks_for(path))
                   for path, _n, _handler in self._evidence
                   if path not in self._hives]
        if not pending:
            return
        for path, unlocks in pending:
            self._searched_unlocked[path] = sorted(unlocks)
        self._finder = _HiveFinder(pending, self)
        self._finder.found.connect(self._hives_found)
        self._finder.start()

    def shutdown(self):
        for thread in (self._finder, self._loader):
            if thread is not None and thread.isRunning():
                thread.requestInterruption()
                thread.wait(10000)

    def wait_for_search(self, timeout_ms=60000):
        """For tests and scripts: block until every evidence is searched."""
        if self._finder is not None:
            self._finder.wait(timeout_ms)
        QApplication.processEvents()

    def _hives_found(self, path, hives):
        if path not in {p for p, _n, _h in self._evidence}:
            return
        self._hives[path] = hives
        self._fill_evidence()

    def _fill_evidence(self):
        selector = self.evidenceSelector
        selector.blockSignals(True)
        selector.clear()
        for path, name, _handler in self._evidence:
            hives = self._hives.get(path)
            note = ('searching…' if hives is None else
                    'no Windows registry' if not hives else
                    f"{len(hives)} hive{'s' if len(hives) != 1 else ''}")
            selector.addItem(f"{name} — {note}", path)
        if not self._evidence:
            selector.addItem("No evidence open", None)
        current = self._chosen or self._default_evidence()
        index = selector.findData(current)
        selector.setCurrentIndex(index if index >= 0 else 0)
        selector.setEnabled(bool(self._evidence))
        selector.blockSignals(False)
        self._fill_hives()

    def _default_evidence(self):
        """The first evidence with a registry; else the first."""
        for path, _n, _h in self._evidence:
            if self._hives.get(path):
                return path
        return self._evidence[0][0] if self._evidence else None

    def _evidence_picked(self, _index):
        self._chosen = self.evidenceSelector.currentData()
        self._fill_hives()

    def current_evidence(self):
        path = self.evidenceSelector.currentData()
        for item in self._evidence:
            if item[0] == path:
                return item
        return None

    def _fill_hives(self):
        selector = self.hiveSelector
        previous = selector.currentData()
        selector.clear()
        evidence = self.current_evidence()
        hives = self._hives.get(evidence[0]) if evidence else None
        if evidence is None:
            selector.addItem("—", None)
        elif hives is None:
            selector.addItem("Looking for hives…", None)
        elif not hives:
            selector.addItem("No Windows registry on this evidence", None)
        else:
            for index, hive in enumerate(hives):
                selector.addItem(hive.label, index)
                selector.setItemData(index, f"{hive.path}  ·  "
                                     f"{hive.size:,} bytes", Qt.ToolTipRole)
            if previous is not None and previous < len(hives):
                selector.setCurrentIndex(previous)
        ready = bool(hives)
        selector.setEnabled(ready)
        self.loadHiveButton.setEnabled(ready and not (
            self._loader is not None and self._loader.isRunning()))

    def selected_hive(self):
        evidence = self.current_evidence()
        index = self.hiveSelector.currentData()
        if evidence is None or index is None:
            return None, None
        return evidence, self._hives[evidence[0]][index]

    def select_hive(self, evidence_path, name, user=''):
        """Choose a hive by evidence, name and user (for tests and links).
        True when it is there."""
        index = self.evidenceSelector.findData(evidence_path)
        if index < 0:
            return False
        self.evidenceSelector.setCurrentIndex(index)
        self._evidence_picked(index)
        for position, hive in enumerate(self._hives.get(evidence_path)
                                        or []):
            if hive.name == name and (not user or hive.user == user):
                self.hiveSelector.setCurrentIndex(position)
                return True
        return False

    # --- reading -------------------------------------------------------------

    def load_selected_hive(self):
        """Start reading the selected hive; the tree fills in when it arrives."""
        evidence, hive = self.selected_hive()
        if hive is None:
            return
        if self._loader is not None and self._loader.isRunning():
            self._loader.requestInterruption()
            self._loader.wait(2000)
        name = evidence[1]
        self.statusMessage.emit(f"Reading {hive.label} from {name}…")
        self.loadHiveButton.setEnabled(False)
        # No placeholder row here: progress goes to the window's status bar,
        # and a tree entry saying "Reading..." reads like a registry key.
        self.treeWidget.clear()
        self._loader = _HiveLoader(evidence[0], self.unlocks_for(evidence[0]),
                                   hive, self)
        self._loader.loaded.connect(
            lambda root, facts: self._on_hive_loaded(evidence, hive, root,
                                                     facts))
        self._loader.failed.connect(self._on_hive_failed)
        self._loader.finished.connect(self._on_load_finished)
        self._loader.start()

    def wait_for_load(self, timeout_ms=60000):
        """For tests and scripts: block until the hive is read and shown."""
        if self._loader is not None:
            self._loader.wait(timeout_ms)
        QApplication.processEvents()

    def _on_load_finished(self):
        """Re-enable the button once the reader stops, however it ended."""
        self.loadHiveButton.setEnabled(bool(self.selected_hive()[1]))

    def _on_hive_loaded(self, evidence, hive, root_key, facts):
        path, name, _handler = evidence
        self.shown = (path, hive)
        self.display_registry_hive(hive.label, root_key)
        root = self.treeWidget.topLevelItem(0)
        root.setToolTip(0, f"{name}: {hive.path}")
        self._source_rows = [("Evidence", name), ("File", hive.path)]
        if hive.volume:
            self._source_rows.append(("Volume", hive.volume))
        if hive.user:
            self._source_rows.append(("User profile", hive.user))
        if facts.get('applied'):
            self._source_rows.append((
                "Transaction logs", f"{facts['applied']} change(s) applied "
                f"from {', '.join(facts.get('logs') or [])} -- the hive as "
                f"Windows last had it"))
        try:
            count = len(root_key.subkeys())
            self.statusMessage.emit(
                f"{hive.label} from {name} loaded  ·  {count} top-level keys"
                + (f"  ·  {facts['applied']} change(s) applied from its "
                   f"transaction logs" if facts.get('applied') else ''))
        except Exception:
            self.statusMessage.emit(f"{hive.label} loaded")
        self._on_load_finished()

    def _on_hive_failed(self, message):
        self.treeWidget.clear()
        self.statusMessage.emit(message)
        self._on_load_finished()

    def display_registry_hive(self, hive_name, root_key):
        """Show the hive's root. Everything below it fills in on demand.

        This used to walk the entire hive up front, building a QTreeWidgetItem
        for every key and value it contained. A SOFTWARE hive holds tens of
        thousands of those, all created on the UI thread, which is what froze
        the window even after the file reading moved to a worker -- and almost
        all of it was thrown away unread, since an examiner opens a handful of
        branches.
        """
        self.treeWidget.clear()
        hive_item = QTreeWidgetItem(self.treeWidget, [hive_name])
        hive_item.setIcon(0, icons.icon(icons.REGISTRY_HIVE))
        hive_item.setData(0, Qt.UserRole, root_key)
        self._mark_unpopulated(hive_item, root_key)
        hive_item.setExpanded(True)

    def _mark_unpopulated(self, item, registry_key):
        """Give a node an expand arrow without building its children yet."""
        try:
            has_content = bool(registry_key.subkeys()) or bool(registry_key.values())
        except Exception:
            has_content = False
        item.setChildIndicatorPolicy(
            QTreeWidgetItem.ShowIndicator if has_content
            else QTreeWidgetItem.DontShowIndicator)
        item.setData(0, self.POPULATED_ROLE, False)

    def _on_item_expanded(self, item):
        """Fill in a node's children the first time it is opened."""
        if item.data(0, self.POPULATED_ROLE):
            return
        item.setData(0, self.POPULATED_ROLE, True)

        registry_key = item.data(0, Qt.UserRole)
        if registry_key is None:
            return

        self.treeWidget.setUpdatesEnabled(False)
        try:
            self.display_registry_keys(item, registry_key)
            self.display_registry_values(item, registry_key)
        finally:
            self.treeWidget.setUpdatesEnabled(True)

    def display_registry_keys(self, parent_item, registry_key):
        """Add one level of subkeys. Their own children wait until expanded."""
        try:
            subkeys = registry_key.subkeys()
        except Exception as e:
            logger.error("Could not read subkeys of %s: %s", parent_item.text(0), e)
            return
        key_icon = icons.icon(icons.REGISTRY_KEY)
        for subkey in subkeys:
            item = QTreeWidgetItem(parent_item, [subkey.name()])
            item.setData(0, Qt.UserRole, subkey)
            item.setIcon(0, key_icon)
            self._mark_unpopulated(item, subkey)

    def display_registry_values(self, parent_key_item, registry_key):
        try:
            values = registry_key.values()
        except Exception as e:
            logger.error("Could not read values of %s: %s", parent_key_item.text(0), e)
            return
        value_icon = icons.icon(icons.REGISTRY_VALUE)
        for value in values:
            item = QTreeWidgetItem(parent_key_item, [value.name() or "(Default)"])
            item.setData(0, Qt.UserRole, value)
            item.setIcon(0, value_icon)
            item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
            item.setData(0, self.POPULATED_ROLE, True)

    def display_metadata(self, registry_object):
        metadata = {
            "Name": registry_object.name(),
        }

        # The full key path, which is how a registry finding is cited in a
        # report -- the name alone does not say where in the hive it sits.
        try:
            metadata["Path"] = registry_object.path()
        except Exception as e:
            logger.debug("No path for this key: %s", e)

        metadata["Number of Subkeys"] = len(registry_object.subkeys())
        metadata["Number of Values"] = len(registry_object.values())
        metadata["Last Modified"] = registry_object.timestamp().strftime(
            "%Y-%m-%d %H:%M:%S UTC")

        # Where this hive came from, under every key: a key is only
        # evidence together with the file and device it was read from.
        self.metadataPanel.set_rows(list(metadata.items())
                                    + self._source_rows)

    def setup_table(self, values):
        # Reset and set up table
        self.tableWidget.clear()
        self.tableWidget.setRowCount(len(values))
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels(["Name", "Type", "Value"])

        # Set initial widths to balance out based on common sizes
        self.tableWidget.setColumnWidth(0, 150)  # Name
        self.tableWidget.setColumnWidth(1, 150)  # Type
        self.tableWidget.setColumnWidth(2, 450)  # Value

        # Set dynamic resizing behavior
        header = self.tableWidget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Name column to stretch based on content
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Type column adjusts to fit the content
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Value column stretches with window resize

        # Populate table rows
        for i, value in enumerate(values):
            self.tableWidget.setItem(i, 0, QTableWidgetItem(value.name()))
            self.tableWidget.setItem(i, 1, QTableWidgetItem(str(value.value_type_str())))
            self.tableWidget.setItem(i, 2, QTableWidgetItem(str(value.value())))

    def display_values_in_table(self, values):
        self.setup_table(values)

    def on_item_clicked(self, item, column):
        registry_object = item.data(0, Qt.UserRole)

        if isinstance(registry_object, RegistryKey):
            self.display_metadata(registry_object)
            self.display_values_in_table(registry_object.values())

        elif isinstance(registry_object, RegistryValue):
            self.setup_table([registry_object])

    # clear the window
    def clear(self):
        self.shown = None
        self._source_rows = []
        self.treeWidget.clear()
        self.metadataPanel.clear_rows()
        self.tableWidget.clear()
