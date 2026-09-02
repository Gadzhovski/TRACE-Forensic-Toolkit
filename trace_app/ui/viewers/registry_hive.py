import logging
import os
import tempfile

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QTextEdit, QToolBar, QLabel, \
    QSplitter, QTableWidget, QTableWidgetItem, QComboBox, QSizePolicy, QPushButton, QMenu, QApplication, QHeaderView
from Registry import Registry
from Registry.Registry import RegistryValue, RegistryKey
from trace_app.infra.paths import resource_path
from trace_app.infra.constants import (PANEL_ICON_SIZE, TREE_ICON_SIZE,
                                       TREE_INDENTATION)
from trace_app.ui import icons
from trace_app.ui.widgets.no_focus_delegate import NoFocusDelegate
from trace_app.ui.widgets.tree_branch import BranchTreeWidget
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar
from trace_app.ui.widgets.property_table import PropertyTable

logger = logging.getLogger('TRACE.Registry')



class RegistryExtractor(QWidget):
    def __init__(self, image_handler):
        super().__init__()
        self.image_handler = image_handler
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
        try:
            selectedHive = self.hiveSelector.currentText()

            # Assuming get_partitions returns partitions where Windows is installed
            partitions = self.image_handler.get_partitions()

            if not partitions:
                logger.debug("No partitions found.")
                return

            for partition in partitions:
                start_offset = partition[2]
                fs_type = self.image_handler.get_fs_type(start_offset)
                fs_info = self.image_handler.get_fs_info(start_offset)
                if fs_type == "NTFS":
                    # Modify to only load the selected hive
                    hive_data = self.image_handler.get_registry_hive(fs_info,
                                                                     f"/Windows/System32/config/{selectedHive}")
                    if hive_data:
                        # Temporarily save the hive data to a file and load it
                        with tempfile.NamedTemporaryFile(delete=False) as temp_hive:
                            temp_hive.write(hive_data)
                            temp_hive_path = temp_hive.name

                        # Load the hive
                        with open(temp_hive_path, "rb") as hive_file:
                            reg = Registry.Registry(hive_file)
                            self.display_registry_hive(selectedHive, reg.root())  # Display the selected hive

                        os.remove(temp_hive_path)
        except Exception as e:
            logger.error(f"An error occurred while loading the selected hive: {e}")

    def display_registry_hive(self, hive_name, root_key):
        self.treeWidget.clear()  # Clear the tree before displaying a new hive
        hive_item = QTreeWidgetItem(self.treeWidget, [hive_name])
        hive_item.setIcon(0, icons.icon(icons.REGISTRY_HIVE))
        hive_item.setData(0, Qt.UserRole, root_key)
        self.display_registry_keys(hive_item, root_key)

    def display_registry_keys(self, parent_item, registry_key):
        subkeys = registry_key.subkeys()  # Call the method once and store the result
        items = [QTreeWidgetItem(parent_item, [subkey.name()]) for subkey in subkeys]  # Use list comprehension
        for item, subkey in zip(items, subkeys):
            item.setData(0, Qt.UserRole, subkey)  # Store the key object for later retrieval
            item.setIcon(0, icons.icon(icons.REGISTRY_KEY))
            self.display_registry_keys(item, subkey)
            self.display_registry_values(item, subkey)

    def display_registry_values(self, parent_key_item, registry_key):
        values = registry_key.values()  # Call the method once and store the result
        items = [QTreeWidgetItem(parent_key_item, [value.name() or "(Default)"]) for value in
                 values]  # Use list comprehension
        for item, value in zip(items, values):
            item.setData(0, Qt.UserRole, value)  # Store the value object for later retrieval
            item.setIcon(0, icons.icon(icons.REGISTRY_VALUE))

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
