import os
import tempfile

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QTextEdit, QToolBar, QLabel, \
    QSplitter, QTableWidget, QTableWidgetItem, QComboBox, QSizePolicy, QPushButton, QMenu, QApplication
from Registry import Registry
from Registry.Registry import RegistryValue, RegistryKey


class RegistryExtractor(QWidget):
    def __init__(self, image_handler):
        super().__init__()
        self.image_handler = image_handler
        self.hive_icon = QIcon("Icons/icons8-hive-48.png")
        self.key_icon = QIcon("Icons/icons8-key-48_blue.png")
        self.value_icon = QIcon("Icons/icons8-wasp-48.png")
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()  # Main layout is vertical
        main_layout.setContentsMargins(0, 0, 0, 0)  # Set the margins to 0

        self.setLayout(main_layout)

        # Toolbar Setup
        self.toolbar = QToolBar("Toolbar")
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setStyleSheet("""
            QToolBar {
                background-color: #f5f5f5;  /* White background for a modern look */
                border-bottom: 1px solid #d7d7d7;  /* Light border for subtle separation */
                padding: 5px;  /* Padding inside the toolbar */
            }
            QToolBar::item:hover {
                background-color: #e7e7e7;  /* Light gray background for hover effect */
            }
            QToolBar::item:pressed {
                background-color: #d7d7d7;  /* Slightly darker for pressed effect */
            }
        """)
        main_layout.addWidget(self.toolbar)

        # Icon Setup
        self.icon_label = QLabel()
        self.icon_label.setPixmap(QIcon("Icons/icons8-registry-editor-96.png").pixmap(48, 48))
        self.toolbar.addWidget(self.icon_label)

        # Label Setup
        self.label = QLabel("Registry Extractor")
        self.label.setStyleSheet("""
            QLabel {
                font-size: 20px; /* Slightly larger size for the title */
                color: #37c6d0; /* Hex color for the text */
                font-weight: bold; /* Make the text bold */
                margin-left: 8px; /* Space between icon and label */
            }
        """)
        self.toolbar.addWidget(self.label)

        # add space between label and combobox
        spacer = QLabel()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        # Inside your RegistryExtractor's init_ui method
        self.hiveSelector = QComboBox()
        self.hiveSelector.addItems(
            ["SOFTWARE", "SYSTEM", "SAM", "SECURITY", "DEFAULT", "COMPONENTS"])  # Add more hives as needed
        self.hiveSelector.setStyleSheet("""
            QComboBox {
                border: 1px solid #ced4da;
                border-radius: 4px;
                padding: 5px 10px;
                background-color: #ffffff;
                selection-background-color: #56CCF2;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 25px;
                border-left-width: 1px;
                border-left-color: #ced4da;
                border-left-style: solid;
                border-top-right-radius: 4px;
                border-bottom-right-radius: 4px;
            }
            QComboBox::down-arrow {
                image: url('Icons/icons8-dropdown-48.png');
                width: 16px;  /* Adjust the width of the image */
                height: 16px;  /* Adjust the height of the image */
            }
            QComboBox::hover {
                border: 1px solid #a2a9b1;
            }
        """)
        self.toolbar.addWidget(self.hiveSelector)

        self.loadHiveButton = QPushButton("Load")
        self.loadHiveButton.clicked.connect(self.load_selected_hive)
        self.loadHiveButton.setStyleSheet("""
            QPushButton {
                border: 1px solid #ced4da;
                border-radius: 4px;
                padding: 5px 15px;
                background-color: #ffffff;
                margin-left: 8px; /* Left margin for spacing */
                margin-right: 8px; /* Right margin for spacing */
                width: 25px;
            }
            QPushButton:hover {
                background-color: #e7e7e7;
            }
            QPushButton:pressed {
                background-color: #d7d7d7;
            }
        """)
        self.toolbar.addWidget(self.loadHiveButton)

        # Splitter setup for resizable tree and details panels
        self.splitter = QSplitter(Qt.Horizontal)  # Horizontal splitter for side-by-side layout
        main_layout.addWidget(self.splitter)

        # Tree Widget Setup
        self.treeWidget = QTreeWidget()
        self.treeWidget.header().hide()
        self.splitter.addWidget(self.treeWidget)

        # Details Panel and Table Setup within a Vertical Splitter
        self.detailsSplitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.detailsSplitter)

        # Details Panel Setup
        self.metadataPanel = QTextEdit()
        # hide the name of the text box

        self.metadataPanel.setReadOnly(True)
        self.detailsSplitter.addWidget(self.metadataPanel)

        # Table Setup for displaying values
        self.tableWidget = QTableWidget()

        # set the header to be hidden
        self.tableWidget.horizontalHeader().hide()
        self.tableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
        # Your existing setup code
        self.tableWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tableWidget.customContextMenuRequested.connect(self.onCustomContextMenuRequested)

        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.setStyleSheet("""
            QTableWidget {
                border: 1px solid #d7d7d7;  /* Light border for subtle separation */
                background-color: #ffffff;  /* White background for the sections */
                gridline-color: #d7d7d7;  /* Light gridlines */
            }
            QTableWidget::item {
                padding: 5px;  /* Padding inside each cell */
            }
            QTableWidget::item:selected {
                background-color: #e7e7e7;  /* Light gray background for selected items */
                color: black;  /* Set the text color to black */
            }
            QHeaderView::section {
                background-color: #e7e7e7;  /* gray background for the headers */
                color: black;  /* Set the text color to white */
                padding: 5px;  /* Add some padding */
                border: 1px solid #d7d7d7;  /* Light border for subtle separation */
            }
        """)

        self.detailsSplitter.addWidget(self.tableWidget)

        # Set the initial stretch factors for splitter panels if needed
        self.detailsSplitter.setStretchFactor(0, 1)  # Set the initial stretch factor for the details panel
        self.detailsSplitter.setStretchFactor(1, 1)  # Set the initial stretch factor for the table widget

        # Connect treeview selection change to the slot
        self.treeWidget.itemClicked.connect(self.on_item_clicked)

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
                print("No partitions found.")
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
            print(f"An error occurred while loading the selected hive: {e}")

    def display_registry_hive(self, hive_name, root_key):
        self.treeWidget.clear()  # Clear the tree before displaying a new hive
        hive_item = QTreeWidgetItem(self.treeWidget, [hive_name])
        hive_item.setIcon(0, self.hive_icon)
        hive_item.setData(0, Qt.UserRole, root_key)
        self.display_registry_keys(hive_item, root_key)


    def display_registry_keys(self, parent_item, registry_key):
        subkeys = registry_key.subkeys()  # Call the method once and store the result
        items = [QTreeWidgetItem(parent_item, [subkey.name()]) for subkey in subkeys]  # Use list comprehension
        for item, subkey in zip(items, subkeys):
            item.setData(0, Qt.UserRole, subkey)  # Store the key object for later retrieval
            item.setIcon(0, self.key_icon)
            self.display_registry_keys(item, subkey)
            self.display_registry_values(item, subkey)

    def display_registry_values(self, parent_key_item, registry_key):
        values = registry_key.values()  # Call the method once and store the result
        items = [QTreeWidgetItem(parent_key_item, [value.name() or "(Default)"]) for value in values]  # Use list comprehension
        for item, value in zip(items, values):
            item.setData(0, Qt.UserRole, value)  # Store the value object for later retrieval
            item.setIcon(0, self.value_icon)


    def display_metadata(self, registry_object):
        metadata = {
            "Name": registry_object.name(),
            "Number of Subkeys": len(registry_object.subkeys()),
            "Number of Values": len(registry_object.values()),
            "Last Modified": registry_object.timestamp().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Start with an HTML structure for styling
        details = '<html><head/><body>'
        details += '<p style="font-size:16px; "><b>Metadata Information</b></p>'

        # Iterate through metadata to add each item with styling
        for key, value in metadata.items():
            details += f'<p style="margin-left: 10px;"><b>{key}:</b> {value}</p>'

        details += '</body></html>'

        self.metadataPanel.setHtml(details)


    def setup_table(self, values):
        self.tableWidget.clear()  # Clear previous content
        self.tableWidget.setRowCount(len(values))  # Set row count based on the number of values
        self.tableWidget.setColumnCount(3)  # Name and Data columns
        self.tableWidget.setHorizontalHeaderLabels(["Name", "Type", "Value"])
        self.tableWidget.horizontalHeader().show()
        self.tableWidget.setColumnWidth(0, 150)  # Set the width of the first column to 200 pixels
        self.tableWidget.setColumnWidth(1, 100)  # Set the width of the second column to 100 pixels

        for i, value in enumerate(values):
            self.tableWidget.setItem(i, 0, QTableWidgetItem(value.name()))
            self.tableWidget.setItem(i, 1, QTableWidgetItem(str(value.value_type_str())))
            self.tableWidget.setItem(i, 2, QTableWidgetItem(str(value.value())))

        self.tableWidget.resizeColumnToContents(2)

    def display_values_in_table(self, values):
        self.setup_table(values)

    def on_item_clicked(self, item, column):
        # Retrieve the stored RegistryKey or RegistryValue object
        registry_object = item.data(0, Qt.UserRole)

        if isinstance(registry_object, RegistryKey):
            self.display_metadata(registry_object)
            self.display_values_in_table(registry_object.values())

        elif isinstance(registry_object, RegistryValue):
            # If a value is clicked, you might want to do something specific
            # For this example, let's clear the table and show just this value
            self.setup_table([registry_object])


    #clear the window
    def clear(self):
        self.treeWidget.clear()
        self.metadataPanel.clear()
        self.tableWidget.clear()



    # def on_item_clicked(self, item, column):
    #     # Retrieve the stored RegistryKey or RegistryValue object
    #     registry_object = item.data(0, Qt.UserRole)
    #
    #     if isinstance(registry_object, RegistryKey):
    #         self.display_metadata(registry_object)
    #         self.display_values_in_table(registry_object.values())
    #
    #     elif isinstance(registry_object, RegistryValue):
    #         # If a value is clicked, you might want to do something specific
    #         # For this example, let's clear the table and show just this value
    #         self.tableWidget.clear()  # Clear previous content
    #         self.tableWidget.setRowCount(1)  # Set row count for a single value
    #         self.tableWidget.setColumnCount(3)  # Name and Data columns
    #         self.tableWidget.setHorizontalHeaderLabels(["Name", "Type", "Value"])
    #         self.tableWidget.horizontalHeader().show()
    #         self.tableWidget.setColumnWidth(0, 150)  # Set the width of the first column to 200 pixels
    #         self.tableWidget.setColumnWidth(1, 100)  # Set the width of the second column to 100 pixels
    #         self.tableWidget.setItem(0, 0, QTableWidgetItem(registry_object.name()))
    #         self.tableWidget.setItem(0, 1, QTableWidgetItem(str(registry_object.value_type_str())))
    #         self.tableWidget.setItem(0, 2, QTableWidgetItem(str(registry_object.value())))
    #         self.tableWidget.resizeColumnToContents(2)

    # def display_values_in_table(self, values):
    #     self.tableWidget.clear()  # Clear previous content
    #     self.tableWidget.setRowCount(len(values))  # Set row count based on the number of values
    #     self.tableWidget.setColumnCount(3)  # Name and Data columns
    #     self.tableWidget.setHorizontalHeaderLabels(["Name", "Type", "Value"])
    #     self.tableWidget.horizontalHeader().show()
    #     self.tableWidget.setColumnWidth(0, 150)  # Set the width of the first column to 200 pixels
    #     self.tableWidget.setColumnWidth(1, 100)  # Set the width of the second column to 100 pixels
    #
    #     for i, value in enumerate(values):
    #         self.tableWidget.setItem(i, 0, QTableWidgetItem(value.name()))
    #         self.tableWidget.setItem(i, 1, QTableWidgetItem(str(value.value_type_str())))
    #         self.tableWidget.setItem(i, 2, QTableWidgetItem(str(value.value())))
    #
    #     self.tableWidget.resizeColumnToContents(2)


    # def display_registry_keys(self, parent_item, registry_key):
    #     for subkey in registry_key.subkeys():
    #         key_item = QTreeWidgetItem(parent_item, [subkey.name()])
    #         key_item.setData(0, Qt.UserRole, subkey)  # Store the key object for later retrieval
    #         key_item.setIcon(0, self.key_icon)
    #         num_subkeys = len(subkey.subkeys())
    #         num_subvalues = len(subkey.values())
    #         self.display_registry_keys(key_item, subkey)
    #         self.display_registry_values(key_item, subkey)
    #
    # def display_registry_values(self, parent_key_item, registry_key):
    #     for value in registry_key.values():
    #         value_name = value.name() or "(Default)"
    #         value_item = QTreeWidgetItem(parent_key_item, [f"{value_name}"])
    #         value_item.setData(0, Qt.UserRole, value)  # Store the value object for later retrieval
    #         value_item.setIcon(0, self.value_icon)