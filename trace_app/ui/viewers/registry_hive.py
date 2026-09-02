import logging
import os
import tempfile

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



class _HiveLoader(QThread):
    """Reads a registry hive out of the image, off the UI thread.

    Extracting a hive walks every partition, pulls the file out of NTFS and
    parses it. On a large image that is seconds of work, and it used to run in
    the click handler -- so the whole window stopped repainting until it
    finished. Only the reading happens here; the tree is built on the UI
    thread, where it has to be.
    """

    #: (hive name, parsed root key) on success.
    loaded = Signal(str, object)
    #: A message to show when nothing could be read.
    failed = Signal(str)

    def __init__(self, image_handler, hive_name, parent=None):
        super().__init__(parent)
        self.image_handler = image_handler
        self.hive_name = hive_name

    def run(self):
        temp_hive_path = None
        try:
            partitions = self.image_handler.get_partitions()
            if not partitions:
                self.failed.emit("No partitions found in this image.")
                return

            for partition in partitions:
                start_offset = partition[2]
                if self.isInterruptionRequested():
                    return
                if self.image_handler.get_fs_type(start_offset) != "NTFS":
                    continue

                fs_info = self.image_handler.get_fs_info(start_offset)
                hive_data = self.image_handler.get_registry_hive(
                    fs_info, f"/Windows/System32/config/{self.hive_name}")
                if not hive_data:
                    continue

                with tempfile.NamedTemporaryFile(delete=False) as temp_hive:
                    temp_hive.write(hive_data)
                    temp_hive_path = temp_hive.name

                with open(temp_hive_path, "rb") as hive_file:
                    reg = Registry.Registry(hive_file)
                    if not self.isInterruptionRequested():
                        self.loaded.emit(self.hive_name, reg.root())
                return

            self.failed.emit(f"{self.hive_name} was not found in this image.")
        except Exception as e:
            logger.error("An error occurred while loading the selected hive: %s", e)
            self.failed.emit(f"Could not read {self.hive_name}: {e}")
        finally:
            if temp_hive_path and os.path.exists(temp_hive_path):
                try:
                    os.remove(temp_hive_path)
                except OSError:
                    pass


class RegistryExtractor(QWidget):
    #: Item data slot recording whether a node's children have been built.
    POPULATED_ROLE = Qt.UserRole + 1

    def __init__(self, image_handler):
        super().__init__()
        self.image_handler = image_handler
        #: The running hive reader, retained so it is not collected mid-read.
        self._loader = None
        # Looked up on each use rather than cached here: an icon fetched once
        # keeps the tint of whatever theme was active at construction, so
        # these stayed light-theme grey after a switch to dark.
        self.init_ui()

    def set_image_handler(self, image_handler):
        """Point this viewer at a newly loaded image."""
        self.image_handler = image_handler

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

        self.hiveSelector = QComboBox()
        self.hiveSelector.addItems(["SOFTWARE", "SYSTEM", "SAM", "SECURITY", "DEFAULT", "COMPONENTS"])
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

    def load_selected_hive(self):
        """Start reading the selected hive; the tree fills in when it arrives."""
        if self.image_handler is None:
            return

        if self._loader is not None and self._loader.isRunning():
            self._loader.requestInterruption()
            self._loader.wait(2000)

        hive = self.hiveSelector.currentText()
        self.loadHiveButton.setEnabled(False)
        self.treeWidget.clear()
        placeholder = QTreeWidgetItem(self.treeWidget, [f"Reading {hive}..."])
        placeholder.setDisabled(True)

        self._loader = _HiveLoader(self.image_handler, hive, self)
        self._loader.loaded.connect(self._on_hive_loaded)
        self._loader.failed.connect(self._on_hive_failed)
        self._loader.finished.connect(self._on_load_finished)
        self._loader.start()

    def _on_load_finished(self):
        """Re-enable the button once the reader stops, however it ended."""
        self.loadHiveButton.setEnabled(True)

    def _on_hive_loaded(self, hive_name, root_key):
        self.display_registry_hive(hive_name, root_key)
        self._on_load_finished()

    def _on_hive_failed(self, message):
        self.treeWidget.clear()
        item = QTreeWidgetItem(self.treeWidget, [message])
        item.setDisabled(True)
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
            "Number of Subkeys": len(registry_object.subkeys()),
            "Number of Values": len(registry_object.values()),
            "Last Modified": registry_object.timestamp().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Start with an HTML structure for styling
        self.metadataPanel.set_rows(list(metadata.items()))

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
        self.treeWidget.clear()
        self.metadataPanel.clear_rows()
        self.tableWidget.clear()
